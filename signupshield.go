// Package signupshield is the official Go SDK for the SignupShield API.
// Stop fake signups with one API call.
//
// Usage:
//
//	client := signupshield.New(os.Getenv("SIGNUPSHIELD_API_KEY"))
//	result, err := client.Score(ctx, signupshield.ScoreParams{
//	    Email: "jane@example.com",
//	    IP:    "8.8.8.8",
//	})
//	if err != nil {
//	    return err
//	}
//	if result.Risk == signupshield.RiskHigh {
//	    return errors.New("signup blocked")
//	}
package signupshield

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL    = "https://api.signupshield.dev"
	defaultTimeout    = 5 * time.Second
	defaultMaxRetries = 3
	userAgent         = "signupshield-go/1.4.0"
)

// Risk levels returned by the API.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// IPReputation values returned by the API.
const (
	IPResidential = "residential"
	IPDatacenter  = "datacenter"
	IPProxy       = "proxy"
	IPTor         = "tor"
)

// Client is the SignupShield API client.
type Client struct {
	apiKey     string
	baseURL    string
	maxRetries int
	http       *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(url, "/") }
}

// WithTimeout sets the HTTP request timeout. Default: 5s.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// WithMaxRetries sets the maximum number of retries on 429 / 5xx. Default: 3.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// New creates a new Client with the given API key and optional Options.
// Panics if apiKey is empty.
func New(apiKey string, opts ...Option) *Client {
	if apiKey == "" {
		panic("signupshield: apiKey must not be empty")
	}
	c := &Client{
		apiKey:     apiKey,
		baseURL:    defaultBaseURL,
		maxRetries: defaultMaxRetries,
		http:       &http.Client{Timeout: defaultTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ScoreParams is the request payload for the /v1/score endpoint.
type ScoreParams struct {
	Email string `json:"email"`
	// IP is optional but improves scoring accuracy.
	IP string `json:"ip,omitempty"`
}

// ScoreResult is the response from the /v1/score endpoint.
type ScoreResult struct {
	Score        int    `json:"score"`
	Risk         string `json:"risk"`
	Disposable   bool   `json:"disposable"`
	FreeProvider bool   `json:"free_provider"`
	MXValid      bool   `json:"mx_valid"`
	IPReputation string `json:"ip_reputation"`
}

// Score evaluates a single email + optional IP pair.
func (c *Client) Score(ctx context.Context, params ScoreParams) (*ScoreResult, error) {
	var result ScoreResult
	if err := c.post(ctx, "/v1/score", params, &result, 0); err != nil {
		return nil, err
	}
	return &result, nil
}

// BatchItem is one item in a batch request.
type BatchItem struct {
	Email string `json:"email"`
	IP    string `json:"ip,omitempty"`
}

// BatchParams is the request payload for the /v1/batch endpoint.
type BatchParams struct {
	// Items holds up to 100 email/IP pairs.
	Items []BatchItem `json:"items"`
}

// BatchResult is the response from the /v1/batch endpoint.
type BatchResult struct {
	Results []ScoreResult `json:"results"`
}

// Batch evaluates up to 100 email/IP pairs in a single request.
func (c *Client) Batch(ctx context.Context, params BatchParams) (*BatchResult, error) {
	var result BatchResult
	if err := c.post(ctx, "/v1/batch", params, &result, 0); err != nil {
		return nil, err
	}
	return &result, nil
}

// APIError is returned when the API responds with a non-2xx status.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("signupshield: %s (HTTP %d, code=%s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("signupshield: HTTP %d", e.Status)
}

// RateLimitError is returned after exhausting retries on HTTP 429.
type RateLimitError struct {
	APIError
	RetryAfter time.Duration
}

func (c *Client) post(ctx context.Context, path string, body, out any, attempt int) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("signupshield: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("signupshield: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("signupshield: do request: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("signupshield: read response: %w", err)
	}

	if res.StatusCode == http.StatusTooManyRequests && attempt < c.maxRetries {
		retryAfter := parseRetryAfter(res.Header.Get("Retry-After"))
		if attempt == c.maxRetries-1 {
			apiErr := parseAPIError(res.StatusCode, raw)
			return &RateLimitError{APIError: *apiErr, RetryAfter: retryAfter}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryAfter):
		}
		return c.post(ctx, path, body, out, attempt+1)
	}

	if res.StatusCode >= 500 && attempt < c.maxRetries {
		backoff := time.Duration(1<<attempt) * 200 * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		return c.post(ctx, path, body, out, attempt+1)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return parseAPIError(res.StatusCode, raw)
	}

	return json.Unmarshal(raw, out)
}

func parseAPIError(status int, body []byte) *APIError {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	return &APIError{Status: status, Code: payload.Error.Code, Message: payload.Error.Message}
}

func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return time.Second
	}
	secs, err := strconv.Atoi(header)
	if err != nil || secs < 0 {
		return time.Second
	}
	return time.Duration(secs) * time.Second
}
