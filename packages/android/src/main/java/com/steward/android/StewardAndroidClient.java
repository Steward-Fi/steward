package com.steward.android;

import com.steward.sdk.PushSubscriptionInput;
import com.steward.sdk.StewardClient;
import java.util.Map;

public final class StewardAndroidClient {
    private final StewardClient client;

    public StewardAndroidClient(StewardClient client) {
        if (client == null) {
            throw new IllegalArgumentException("client is required");
        }
        this.client = client;
    }

    public static StewardAndroidClient withBearerToken(String baseUrl, String bearerToken) {
        return new StewardAndroidClient(
            new StewardClient(StewardClient.config(baseUrl).bearerToken(bearerToken).build())
        );
    }

    public Map<String, Object> registerFcmPushToken(DevicePushRegistration registration) {
        PushSubscriptionInput.Builder builder = PushSubscriptionInput.builder("fcm", registration.getToken())
            .platform("android");
        if (registration.getTenantId() != null) {
            builder.tenantId(registration.getTenantId());
        }
        if (registration.getDeviceId() != null) {
            builder.deviceId(registration.getDeviceId());
        }
        if (registration.getAppId() != null) {
            builder.appId(registration.getAppId());
        }
        if (registration.getLocale() != null) {
            builder.locale(registration.getLocale());
        }
        if (registration.getTimezone() != null) {
            builder.timezone(registration.getTimezone());
        }
        if (registration.getMetadata() != null) {
            builder.metadata(registration.getMetadata());
        }
        return client.registerUserPushSubscription(builder.build());
    }

    public Map<String, Object> listPushSubscriptions() {
        return client.listUserPushSubscriptions();
    }

    public Map<String, Object> revokePushSubscription(String subscriptionId) {
        return client.revokeUserPushSubscription(subscriptionId);
    }

    public StewardClient rawClient() {
        return client;
    }
}

