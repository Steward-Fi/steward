package steward

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL              string
	APIKey               string
	BearerToken          string
	PlatformKey          string
	AppID                string
	AppSecret            string
	TenantID             string
	RequestSigningSecret string
	RequestSigningKeyID  string
	HTTPClient           *http.Client
	Now                  func() time.Time
	NewID                func() string
}

type Client struct {
	baseURL string
	config  Config
	http    *http.Client
	now     func() time.Time
	newID   func() string
}

type APIError struct {
	Status int
	Data   map[string]any
	Err    string
}

func (e *APIError) Error() string {
	if e.Err != "" {
		return e.Err
	}
	return fmt.Sprintf("steward request failed with status %d", e.Status)
}

type apiEnvelope struct {
	OK    *bool           `json:"ok,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

var sensitivePrefixes = []string{
	"/vault",
	"/agents",
	"/policies",
	"/secrets",
	"/trade",
	"/v1/trade",
	"/approvals",
	"/intents",
	"/user",
	"/webhooks",
	"/tenants",
	"/platform",
	"/condition-sets",
	"/condition_sets",
	"/v1/condition_sets",
}

func NewClient(config Config) (*Client, error) {
	if strings.TrimSpace(config.BaseURL) == "" {
		return nil, errors.New("base URL is required")
	}
	base := strings.TrimRight(config.BaseURL, "/")
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = randomID
	}
	return &Client{baseURL: base, config: config, http: httpClient, now: now, newID: newID}, nil
}

func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	return c.Request(ctx, http.MethodGet, path, nil, query, out)
}

func (c *Client) Post(ctx context.Context, path string, body any, out any) error {
	return c.Request(ctx, http.MethodPost, path, body, nil, out)
}

func (c *Client) Patch(ctx context.Context, path string, body any, out any) error {
	return c.Request(ctx, http.MethodPatch, path, body, nil, out)
}

func (c *Client) Delete(ctx context.Context, path string, out any) error {
	return c.Request(ctx, http.MethodDelete, path, nil, nil, out)
}

func (c *Client) Request(ctx context.Context, method string, path string, body any, query url.Values, out any) error {
	canonicalPath := canonicalPath(path)
	rawBody, err := marshalBody(body)
	if err != nil {
		return err
	}
	target := c.baseURL + canonicalPath
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if rawBody != nil {
		reader = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	c.applyHeaders(req, method, canonicalPath, rawBody)
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return decodeResponse(res.StatusCode, payload, out)
}

func (c *Client) applyHeaders(req *http.Request, method string, path string, body []byte) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	switch {
	case c.config.PlatformKey != "":
		req.Header.Set("X-Steward-Platform-Key", c.config.PlatformKey)
	case c.config.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	case c.config.AppID != "" && c.config.AppSecret != "":
		encoded := base64.StdEncoding.EncodeToString([]byte(c.config.AppID + ":" + c.config.AppSecret))
		req.Header.Set("Authorization", "Basic "+encoded)
		req.Header.Set("X-Steward-App-Id", c.config.AppID)
	case c.config.APIKey != "":
		req.Header.Set("X-Steward-Key", c.config.APIKey)
	}
	if c.config.TenantID != "" {
		req.Header.Set("X-Steward-Tenant", c.config.TenantID)
	}
	if c.config.RequestSigningSecret != "" && isSensitiveMutation(path, method) {
		timestamp := req.Header.Get("X-Steward-Request-Timestamp")
		if timestamp == "" {
			timestamp = fmt.Sprintf("%d", c.now().Unix())
			req.Header.Set("X-Steward-Request-Timestamp", timestamp)
		}
		idempotencyKey := req.Header.Get("Idempotency-Key")
		if idempotencyKey == "" {
			idempotencyKey = c.newID()
			req.Header.Set("Idempotency-Key", idempotencyKey)
		}
		if c.config.RequestSigningKeyID != "" && req.Header.Get("X-Steward-Signing-Key-Id") == "" {
			req.Header.Set("X-Steward-Signing-Key-Id", c.config.RequestSigningKeyID)
		}
		bodyHashBytes := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(bodyHashBytes[:])
		canonical := strings.Join([]string{strings.ToUpper(method), path, timestamp, idempotencyKey, bodyHash}, "\n")
		mac := hmac.New(sha256.New, []byte(c.config.RequestSigningSecret))
		mac.Write([]byte(canonical))
		req.Header.Set("X-Steward-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))
	}
}

func decodeResponse(status int, payload []byte, out any) error {
	if len(payload) == 0 {
		if status >= 400 {
			return &APIError{Status: status}
		}
		return nil
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("invalid steward JSON response: %w", err)
	}
	if status >= 400 || (envelope.OK != nil && !*envelope.OK) {
		data := map[string]any{}
		_ = json.Unmarshal(payload, &data)
		return &APIError{Status: status, Err: envelope.Error, Data: data}
	}
	if out == nil {
		return nil
	}
	if len(envelope.Data) > 0 {
		return json.Unmarshal(envelope.Data, out)
	}
	return json.Unmarshal(payload, out)
}

func marshalBody(body any) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	return json.Marshal(body)
}

func canonicalPath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func isSensitiveMutation(path string, method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
