package steward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// SEC-126: a port change is cross-origin and must not be followed at all. Header
// stripping alone would still make a server-side SDK caller an SSRF primitive.
func TestCrossOriginRedirectIsRefused(t *testing.T) {
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
	if err := client.Get(context.Background(), "/accounts", nil, &out); err == nil || !strings.Contains(err.Error(), "refusing cross-origin") {
		t.Fatalf("expected cross-origin redirect refusal, got %v", err)
	}
	if redirected != nil {
		t.Fatal("cross-origin redirect target was contacted")
	}
}

func TestRedirectPolicyRejectsDowngradeCredentialsAndExcessiveChains(t *testing.T) {
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	downgrade, _ := http.NewRequest(http.MethodGet, "http://api.example.test/harvest", nil)
	downgrade.Header.Set("Authorization", "Bearer user-token")
	downgrade.Header.Set("X-Steward-Key", "tenant-key")
	downgrade.Header.Set("X-Steward-Signature", "v1=deadbeef")
	if err := stewardRedirectPolicy(downgrade, []*http.Request{original}); err == nil {
		t.Fatal("HTTPS downgrade was accepted")
	}
	credentialURL, _ := url.Parse("https://user:password@api.example.test/other")
	credentialRedirect := &http.Request{URL: credentialURL}
	if err := stewardRedirectPolicy(credentialRedirect, []*http.Request{original}); err == nil {
		t.Fatal("credential-bearing redirect was accepted")
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = original
	}
	sameOriginURL, _ := url.Parse("https://api.example.test/other")
	if err := stewardRedirectPolicy(&http.Request{URL: sameOriginURL}, via); err == nil {
		t.Fatal("excessive redirect chain was accepted")
	}
}

func TestCustomHTTPClientCannotDisableRedirectBoundary(t *testing.T) {
	customCalled := false
	custom := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		customCalled = true
		return nil
	}}
	client, err := NewClient(Config{BaseURL: "https://api.example.test", HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	cross, _ := http.NewRequest(http.MethodGet, "https://evil.example/harvest", nil)
	if err := client.http.CheckRedirect(cross, []*http.Request{original}); err == nil {
		t.Fatal("custom client disabled mandatory cross-origin refusal")
	}
	if customCalled {
		t.Fatal("custom redirect callback ran before mandatory boundary")
	}
}

func TestCustomRedirectPolicyCannotMutatePastRedirectBoundary(t *testing.T) {
	custom := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		mutated, err := url.Parse("http://127.0.0.1:1/internal-metadata")
		if err != nil {
			t.Fatal(err)
		}
		req.URL = mutated
		return nil
	}}
	client, err := NewClient(Config{BaseURL: "https://api.example.test", HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "https://api.example.test/other", nil)
	if err := client.http.CheckRedirect(redirect, []*http.Request{original}); err == nil || !strings.Contains(err.Error(), "refusing cross-origin") {
		t.Fatalf("caller mutation bypassed redirect boundary: %v", err)
	}
}

func TestCustomRedirectPolicyCannotMutateOriginalAndTargetPastBoundary(t *testing.T) {
	custom := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		evil, _ := url.Parse("https://evil.example.test/harvest")
		req.URL = evil
		// Mutating the original request used to defeat the post-callback check,
		// because both sides of the comparison were read after this callback.
		via[0].URL = evil
		return nil
	}}
	client, err := NewClient(Config{BaseURL: "https://api.example.test", HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "https://api.example.test/other", nil)
	if err := client.http.CheckRedirect(redirect, []*http.Request{original}); err == nil || !strings.Contains(err.Error(), "refusing cross-origin") {
		t.Fatalf("caller rewrote both redirect origins past boundary: %v", err)
	}
}

func TestCustomRedirectPolicyCannotPoisonOriginForLaterHop(t *testing.T) {
	customCalls := 0
	custom := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		customCalls++
		if customCalls == 1 {
			evil, _ := url.Parse("https://evil.example.test/poisoned-origin")
			via[0].URL = evil
		}
		return nil
	}}
	client, err := NewClient(Config{BaseURL: "https://api.example.test", HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	firstHop, _ := http.NewRequest(http.MethodGet, "https://api.example.test/other", nil)
	if err := client.http.CheckRedirect(firstHop, []*http.Request{original}); err != nil {
		t.Fatalf("same-origin first hop was rejected: %v", err)
	}
	secondHop, _ := http.NewRequest(http.MethodGet, "https://evil.example.test/harvest", nil)
	if err := client.http.CheckRedirect(secondHop, []*http.Request{original, firstHop}); err == nil || !strings.Contains(err.Error(), "refusing cross-origin") {
		t.Fatalf("poisoned prior hop became the redirect origin: %v", err)
	}
	if customCalls != 1 {
		t.Fatalf("custom policy ran for rejected cross-origin second hop: %d calls", customCalls)
	}
}

func TestRedirectPolicyRejectsMissingOriginMetadata(t *testing.T) {
	original, _ := http.NewRequest(http.MethodGet, "https://api.example.test/accounts", nil)
	if err := stewardRedirectPolicy(&http.Request{}, []*http.Request{original}); err == nil {
		t.Fatal("redirect with nil target URL was accepted")
	}
	if err := stewardRedirectPolicy(original, []*http.Request{nil}); err == nil {
		t.Fatal("redirect with nil origin request was accepted")
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
