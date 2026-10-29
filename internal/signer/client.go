package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls a signer's HTTP API (used by the coordinator).
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient(baseURL, token string) *Client {
	// Keygen can take a while if the pre-parameter pool is empty.
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 10 * time.Minute}}
}

// APIError is a non-2xx response from a signer.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("signer: %d: %s", e.Status, e.Message) }

func (c *Client) Identity(ctx context.Context) (*IdentityResponse, error) {
	var out IdentityResponse
	return &out, c.do(ctx, http.MethodGet, "/v1/identity", nil, &out)
}

func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	return &out, c.do(ctx, http.MethodGet, "/v1/health", nil, &out)
}

func (c *Client) Keygen(ctx context.Context, req KeygenRequest) (*KeygenResult, error) {
	var out KeygenResult
	return &out, c.do(ctx, http.MethodPost, "/v1/keygen", req, &out)
}

func (c *Client) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	var out SignResult
	return &out, c.do(ctx, http.MethodPost, "/v1/sign", req, &out)
}

// Review and Confirm call the user signer's approval API; create the Client
// with the approval URL and approval token.
func (c *Client) Review(ctx context.Context, req ReviewRequest) (*ReviewResponse, error) {
	var out ReviewResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/approvals/review", req, &out)
}

func (c *Client) Confirm(ctx context.Context, req ConfirmRequest) (*ConfirmResponse, error) {
	var out ConfirmResponse
	return &out, c.do(ctx, http.MethodPost, "/v1/approvals/confirm", req, &out)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(raw, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
