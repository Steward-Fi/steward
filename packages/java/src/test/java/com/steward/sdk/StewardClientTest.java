package com.steward.sdk;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class StewardClientTest {
    public static void main(String[] args) {
        testPlatformKeyCreateUserRequest();
        testBearerPushSubscriptionHelper();
        testSensitiveMutationsAreSignedAndIdempotent();
        testTenantApiKeyAndTenantHeader();
        testApiErrorsIncludeStatusAndPayload();
        System.out.println("StewardClientTest passed");
    }

    private static void testPlatformKeyCreateUserRequest() {
        CaptureTransport transport = new CaptureTransport(200, "{\"ok\":true,\"data\":{\"id\":\"user-1\"}}");
        StewardClient client = new StewardClient(StewardClient.config("https://api.example.test/")
            .platformKey("platform-key")
            .transport(transport)
            .build());

        Map<String, Object> result = client.createUser(CreateUserInput.builder("tenant-1")
            .email("u@example.com")
            .build());

        assertEquals("user-1", result.get("id"));
        assertEquals("https://api.example.test/platform/users", transport.request.getUri().toString());
        assertEquals("POST", transport.request.getMethod());
        assertEquals("platform-key", transport.request.getHeader("X-Steward-Platform-Key"));
        assertEquals("{\"email\":\"u@example.com\",\"tenantId\":\"tenant-1\"}", body(transport.request));
    }

    private static void testBearerPushSubscriptionHelper() {
        CaptureTransport transport = new CaptureTransport(200, "{\"ok\":true,\"data\":{\"subscription\":{\"id\":\"push-1\"}}}");
        StewardClient client = new StewardClient(StewardClient.config("https://api.example.test")
            .bearerToken("user-token")
            .transport(transport)
            .build());

        Map<String, Object> result = client.registerUserPushSubscription(PushSubscriptionInput
            .builder("expo", "ExpoPushToken[abc123abc123abc123]")
            .build());

        @SuppressWarnings("unchecked")
        Map<String, Object> subscription = (Map<String, Object>) result.get("subscription");
        assertEquals("push-1", subscription.get("id"));
        assertEquals("https://api.example.test/user/me/push-subscriptions", transport.request.getUri().toString());
        assertEquals("Bearer user-token", transport.request.getHeader("Authorization"));
        assertEquals("expo", Json.parse(body(transport.request)) instanceof Map<?, ?> map ? map.get("provider") : null);
    }

    private static void testSensitiveMutationsAreSignedAndIdempotent() {
        CaptureTransport transport = new CaptureTransport(200, "{\"ok\":true,\"data\":{\"id\":\"ok\"}}");
        StewardClient client = new StewardClient(StewardClient.config("https://api.example.test")
            .appCredentials("app-1", "secret-1")
            .requestSigningSecret("signing-secret")
            .requestSigningKeyId("key-1")
            .clock(Clock.fixed(Instant.ofEpochSecond(1_779_819_300L), ZoneOffset.UTC))
            .idFactory(() -> "idem-1")
            .transport(transport)
            .build());

        Map<String, Object> body = new HashMap<>();
        body.put("provider", "fcm");
        body.put("token", "fcm-token-123456");
        client.post("/user/me/push-subscriptions", body);

        String auth = transport.request.getHeader("Authorization");
        assertTrue(auth != null && auth.startsWith("Basic "), "basic auth missing");
        assertEquals("app-1", transport.request.getHeader("X-Steward-App-Id"));
        assertEquals("1779819300", transport.request.getHeader("X-Steward-Request-Timestamp"));
        assertEquals("idem-1", transport.request.getHeader("Idempotency-Key"));
        assertEquals("key-1", transport.request.getHeader("X-Steward-Signing-Key-Id"));
        String signature = transport.request.getHeader("X-Steward-Signature");
        assertTrue(signature != null && signature.matches("^v1=[0-9a-f]{64}$"), "bad signature: " + signature);
    }

    private static void testTenantApiKeyAndTenantHeader() {
        CaptureTransport transport = new CaptureTransport(200, "{\"ok\":true,\"data\":{\"id\":\"ok\"}}");
        StewardClient client = new StewardClient(StewardClient.config("https://api.example.test")
            .apiKey("tenant-key")
            .tenantId("tenant-1")
            .transport(transport)
            .build());

        client.get("/platform/users/user-1");

        assertEquals("tenant-key", transport.request.getHeader("X-Steward-Key"));
        assertEquals("tenant-1", transport.request.getHeader("X-Steward-Tenant"));
    }

    private static void testApiErrorsIncludeStatusAndPayload() {
        CaptureTransport transport = new CaptureTransport(403, "{\"ok\":false,\"error\":\"denied\"}");
        StewardClient client = new StewardClient(StewardClient.config("https://api.example.test")
            .apiKey("tenant-key")
            .transport(transport)
            .build());

        try {
            client.get("/platform/users/user-1");
            throw new AssertionError("expected API exception");
        } catch (StewardApiException error) {
            assertEquals(403, error.getStatus());
            assertEquals("denied", error.getMessage());
        }
    }

    private static String body(StewardTransportRequest request) {
        byte[] body = request.getBody();
        return body == null ? "" : new String(body, StandardCharsets.UTF_8);
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("expected " + expected + ", got " + actual);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class CaptureTransport implements StewardTransport {
        private final int status;
        private final String payload;
        private StewardTransportRequest request;

        private CaptureTransport(int status, String payload) {
            this.status = status;
            this.payload = payload;
        }

        @Override
        public StewardTransportResponse send(StewardTransportRequest request) {
            this.request = request;
            return new StewardTransportResponse(status, Map.of("content-type", List.of("application/json")), payload.getBytes(StandardCharsets.UTF_8));
        }
    }
}
