package com.steward.android;

import com.steward.sdk.StewardClient;
import com.steward.sdk.StewardTransportRequest;
import com.steward.sdk.StewardTransportResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

public final class StewardAndroidClientTest {
    public static void main(String[] args) {
        registersFcmPushTokenWithBearerAuth();
        rejectsMissingDeviceToken();
        System.out.println("StewardAndroidClientTest passed");
    }

    private static void registersFcmPushTokenWithBearerAuth() {
        final StewardTransportRequest[] captured = new StewardTransportRequest[1];
        StewardClient raw = new StewardClient(StewardClient.config("https://api.example.test")
            .bearerToken("user-token")
            .timeout(Duration.ofSeconds(5))
            .transport(request -> {
                captured[0] = request;
                return new StewardTransportResponse(
                    200,
                    Map.of("content-type", java.util.List.of("application/json")),
                    "{\"ok\":true,\"data\":{\"subscription\":{\"id\":\"push-1\"}}}".getBytes(StandardCharsets.UTF_8)
                );
            })
            .build());
        StewardAndroidClient client = new StewardAndroidClient(raw);

        Map<String, Object> result = client.registerFcmPushToken(DevicePushRegistration.builder("fcm-token-123")
            .tenantId("tenant-1")
            .deviceId("device-1")
            .appId("fi.steward.app")
            .locale("en-US")
            .timezone("America/New_York")
            .metadata(Map.of("build", "1"))
            .build());

        assertEquals("push-1", ((Map<?, ?>) result.get("subscription")).get("id"), "subscription id");
        assertEquals("POST", captured[0].getMethod(), "method");
        assertEquals("https://api.example.test/user/me/push-subscriptions", captured[0].getUri().toString(), "url");
        assertEquals("Bearer user-token", captured[0].getHeaders().get("Authorization").get(0), "bearer");
        String body = new String(captured[0].getBody(), StandardCharsets.UTF_8);
        assertContains(body, "\"provider\":\"fcm\"");
        assertContains(body, "\"platform\":\"android\"");
        assertContains(body, "\"token\":\"fcm-token-123\"");
        assertContains(body, "\"deviceId\":\"device-1\"");
    }

    private static void rejectsMissingDeviceToken() {
        try {
            DevicePushRegistration.builder("  ");
            throw new AssertionError("expected missing token rejection");
        } catch (IllegalArgumentException expected) {
            assertContains(expected.getMessage(), "token is required");
        }
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + " but got " + actual);
        }
    }

    private static void assertContains(String value, String needle) {
        if (!value.contains(needle)) {
            throw new AssertionError("expected '" + value + "' to contain '" + needle + "'");
        }
    }
}
