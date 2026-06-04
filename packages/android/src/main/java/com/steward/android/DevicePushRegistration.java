package com.steward.android;

import java.util.Map;

public final class DevicePushRegistration {
    private final String token;
    private final String tenantId;
    private final String deviceId;
    private final String appId;
    private final String locale;
    private final String timezone;
    private final Map<String, Object> metadata;

    private DevicePushRegistration(Builder builder) {
        this.token = builder.token;
        this.tenantId = builder.tenantId;
        this.deviceId = builder.deviceId;
        this.appId = builder.appId;
        this.locale = builder.locale;
        this.timezone = builder.timezone;
        this.metadata = builder.metadata;
    }

    public String getToken() {
        return token;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getAppId() {
        return appId;
    }

    public String getLocale() {
        return locale;
    }

    public String getTimezone() {
        return timezone;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public static Builder builder(String token) {
        return new Builder(token);
    }

    public static final class Builder {
        private final String token;
        private String tenantId;
        private String deviceId;
        private String appId;
        private String locale;
        private String timezone;
        private Map<String, Object> metadata;

        private Builder(String token) {
            if (token == null || token.trim().isEmpty()) {
                throw new IllegalArgumentException("token is required");
            }
            this.token = token;
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

        public DevicePushRegistration build() {
            return new DevicePushRegistration(this);
        }
    }
}

