package steward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestCreateUserUsesPlatformKey(t *testing.T) {
	var captured *http.Request
	var capturedBody map[string]any
	client, err := NewClient(Config{
		BaseURL:     "https://api.example.test/",
		PlatformKey: "platform-key",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			if err := json.NewDecoder(req.Body).Decode(&capturedBody); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(200, `{"ok":true,"data":{"id":"user-1"}}`), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	user, err := client.CreateUser(context.Background(), CreateUserInput{
		TenantID: "tenant-1",
		Email:    "u@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user["id"] != "user-1" {
		t.Fatalf("unexpected user: %#v", user)
	}
	if captured.URL.String() != "https://api.example.test/platform/users" {
		t.Fatalf("unexpected URL: %s", captured.URL.String())
	}
	if captured.Method != http.MethodPost {
		t.Fatalf("unexpected method: %s", captured.Method)
	}
	if captured.Header.Get("X-Steward-Platform-Key") != "platform-key" {
		t.Fatalf("platform key missing")
	}
	if capturedBody["tenantId"] != "tenant-1" || capturedBody["email"] != "u@example.com" {
		t.Fatalf("unexpected body: %#v", capturedBody)
	}
}

func TestBearerPushSubscriptionHelper(t *testing.T) {
	var captured *http.Request
	client, err := NewClient(Config{
		BaseURL:     "https://api.example.test",
		BearerToken: "user-token",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			return jsonResponse(200, `{"ok":true,"data":{"subscription":{"id":"push-1"}}}`), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.RegisterUserPushSubscription(context.Background(), PushSubscriptionInput{
		Provider: "expo",
		Token:    "ExpoPushToken[abc123abc123abc123]",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Subscription["id"] != "push-1" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if captured.URL.String() != "https://api.example.test/user/me/push-subscriptions" {
		t.Fatalf("unexpected URL: %s", captured.URL.String())
	}
	if captured.Header.Get("Authorization") != "Bearer user-token" {
		t.Fatalf("bearer token missing")
	}
}

func TestSensitiveMutationsAreSignedAndIdempotent(t *testing.T) {
	var captured *http.Request
	client, err := NewClient(Config{
		BaseURL:              "https://api.example.test",
		AppID:                "app-1",
		AppSecret:            "secret-1",
		RequestSigningSecret: "signing-secret",
		RequestSigningKeyID:  "key-1",
		Now:                  func() time.Time { return time.Unix(1_779_819_300, 0) },
		NewID:                func() string { return "idem-1" },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			return jsonResponse(200, `{"ok":true,"data":{"id":"ok"}}`), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Post(context.Background(), "/user/me/push-subscriptions", map[string]any{
		"provider": "fcm",
		"token":    "fcm-token-123456",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(captured.Header.Get("Authorization"), "Basic ") {
		t.Fatalf("basic auth missing")
	}
	if captured.Header.Get("X-Steward-App-Id") != "app-1" {
		t.Fatalf("app id missing")
	}
	if captured.Header.Get("X-Steward-Request-Timestamp") != "1779819300" {
		t.Fatalf("timestamp missing")
	}
	if captured.Header.Get("Idempotency-Key") != "idem-1" {
		t.Fatalf("idempotency key missing")
	}
	if captured.Header.Get("X-Steward-Signing-Key-Id") != "key-1" {
		t.Fatalf("signing key id missing")
	}
	if got := captured.Header.Get("X-Steward-Signature"); !strings.HasPrefix(got, "v1=") || len(got) != 67 {
		t.Fatalf("bad signature: %s", got)
	}
}

func TestAPIErrorIncludesStatusAndPayload(t *testing.T) {
	client, err := NewClient(Config{
		BaseURL: "https://api.example.test",
		APIKey:  "tenant-key",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return jsonResponse(403, `{"ok":false,"error":"denied"}`), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Get(context.Background(), "/platform/users/user-1", nil, nil)
	var apiErr *APIError
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denied API error, got %v", err)
	}
	if !asAPIError(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("unexpected API error: %#v", err)
	}
}

func asAPIError(err error, target **APIError) bool {
	if err == nil {
		return false
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		return false
	}
	*target = apiErr
	return true
}
