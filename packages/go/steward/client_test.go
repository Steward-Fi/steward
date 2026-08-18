package steward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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

// SEC-049: every SDK's signing-prefix list must cover wallet/account mutations
// in lockstep (Flutter already signed these).
func TestAccountsAndGlobalWalletMutationsAreSigned(t *testing.T) {
	var captured *http.Request
	client, err := NewClient(Config{
		BaseURL:              "https://api.example.test",
		AppID:                "app-1",
		AppSecret:            "secret-1",
		RequestSigningSecret: "signing-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured = req
			return jsonResponse(200, `{"ok":true,"data":{"id":"ok"}}`), nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/accounts", "/global-wallet/consent/approve"} {
		if err := client.Post(context.Background(), path, map[string]any{}, nil); err != nil {
			t.Fatal(err)
		}
		if got := captured.Header.Get("X-Steward-Signature"); !strings.HasPrefix(got, "v1=") || len(got) != 67 {
			t.Fatalf("unsigned mutation %s: signature %q", path, got)
		}
	}
}

// SEC-126: the default HTTP client must not forward credential headers to a
// different origin when a redirect is followed. A port change is cross-origin.
func TestCrossOriginRedirectStripsCredentialHeaders(t *testing.T) {
	var redirected *http.Request
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		redirected = req
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":{"id":"ok"}}`))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL+"/harvest", http.StatusFound)
	}))
	defer redirector.Close()

	client, err := NewClient(Config{BaseURL: redirector.URL, APIKey: "tenant-key"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := client.Get(context.Background(), "/accounts", nil, &out); err != nil {
		t.Fatal(err)
	}
	if redirected == nil {
		t.Fatal("redirect was not followed")
	}
	if got := redirected.Header.Get("X-Steward-Key"); got != "" {
		t.Fatalf("credential header leaked cross-origin: X-Steward-Key=%q", got)
	}
}

func TestSameHostHTTPSDowngradeStripsCredentialHeaders(t *testing.T) {
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	downgrade, _ := http.NewRequest(http.MethodGet, "http://api.example.test/harvest", nil)
	downgrade.Header.Set("Authorization", "Bearer user-token")
	downgrade.Header.Set("X-Steward-Key", "tenant-key")
	downgrade.Header.Set("X-Steward-Signature", "v1=deadbeef")
	if err := stripStewardCredentialsOnCrossHostRedirect(downgrade, []*http.Request{original}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Authorization", "X-Steward-Key", "X-Steward-Signature"} {
		if got := downgrade.Header.Get(name); got != "" {
			t.Fatalf("credential header leaked on HTTPS downgrade: %s=%q", name, got)
		}
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

// SEC-196: the default idempotency-key generator must return crypto-rand
// UUIDs (or an error) — never a predictable timestamp-derived fallback.
func TestRandomIDReturnsCryptoUUIDs(t *testing.T) {
	first, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	uuidShape := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidShape.MatchString(first) {
		t.Fatalf("randomID is not a UUID (timestamp fallback?): %q", first)
	}
	if first == second {
		t.Fatal("randomID produced duplicate ids")
	}
}

// SEC-200: the client must refuse to send credentials to a plaintext
// non-loopback endpoint unless the operator explicitly opts out.
func TestNewClientRejectsPlaintextNonLoopbackBaseURL(t *testing.T) {
	for _, base := range []string{"http://api.example.test", "http://192.168.1.10:3200", "ftp://api.example.test", "https://user:secret@api.example.test"} {
		if _, err := NewClient(Config{BaseURL: base}); err == nil {
			t.Fatalf("expected error for plaintext non-loopback base URL %s", base)
		} else if !strings.Contains(err.Error(), "HTTPS") && !strings.Contains(err.Error(), "credentials") {
			t.Fatalf("unexpected error for %s: %v", base, err)
		}
	}
}

func TestNewClientAllowsHTTPSAndLoopbackBaseURL(t *testing.T) {
	for _, base := range []string{"https://api.example.test", "http://localhost:3200", "http://127.0.0.1:3200", "http://[::1]:3200"} {
		if _, err := NewClient(Config{BaseURL: base}); err != nil {
			t.Fatalf("unexpected error for %s: %v", base, err)
		}
	}
}

func TestNewClientAllowInsecureBaseURLOptsOut(t *testing.T) {
	if _, err := NewClient(Config{BaseURL: "http://api.example.test", AllowInsecureBaseURL: true}); err != nil {
		t.Fatalf("unexpected error with AllowInsecureBaseURL: %v", err)
	}
}
