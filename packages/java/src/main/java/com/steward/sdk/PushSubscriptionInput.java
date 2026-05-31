package com.steward.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

public final class PushSubscriptionInput {
    private final String provider;
    private final String token;
    private final String platform;
    private final String tenantId;
    private final String deviceId;
    private final String appId;
    private final String locale;
    private final String timezone;
    private final Map<String, Object> metadata;

    private PushSubscriptionInput(Builder builder) {
        this.provider = builder.provider;
        this.token = builder.token;
        this.platform = builder.platform;
        this.tenantId = builder.tenantId;
        this.deviceId = builder.deviceId;
        this.appId = builder.appId;
        this.locale = builder.locale;
        this.timezone = builder.timezone;
        this.metadata = builder.metadata;
    }

    Map<String, Object> toMap() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("provider", provider);
        body.put("token", token);
        if (platform != null) {
            body.put("platform", platform);
        }
        if (tenantId != null) {
            body.put("tenantId", tenantId);
        }
        if (deviceId != null) {
            body.put("deviceId", deviceId);
        }
        if (appId != null) {
            body.put("appId", appId);
        }
        if (locale != null) {
            body.put("locale", locale);
        }
        if (timezone != null) {
            body.put("timezone", timezone);
        }
        if (metadata != null) {
            body.put("metadata", metadata);
        }
        return body;
    }

    public static Builder builder(String provider, String token) {
        return new Builder(provider, token);
    }

    public static final class Builder {
        private final String provider;
        private final String token;
        private String platform;
        private String tenantId;
        private String deviceId;
        private String appId;
        private String locale;
        private String timezone;
        private Map<String, Object> metadata;

        private Builder(String provider, String token) {
            this.provider = provider;
            this.token = token;
        }

        public Builder platform(String platform) {
            this.platform = platform;
            return this;
        }

        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        public Builder appId(String appId) {
            this.appId = appId;
            return this;
        }

        public Builder locale(String locale) {
            this.locale = locale;
            return this;
        }

        public Builder timezone(String timezone) {
            this.timezone = timezone;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public PushSubscriptionInput build() {
            return new PushSubscriptionInput(this);
        }
    }
}
