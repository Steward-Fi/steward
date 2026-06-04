package com.steward.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

public final class CreateUserInput {
    private final String tenantId;
    private final String email;
    private final String walletAddress;
    private final Map<String, Object> customMetadata;

    private CreateUserInput(Builder builder) {
        this.tenantId = builder.tenantId;
        this.email = builder.email;
        this.walletAddress = builder.walletAddress;
        this.customMetadata = builder.customMetadata;
    }

    Map<String, Object> toMap() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenantId", tenantId);
        if (email != null) {
            body.put("email", email);
        }
        if (walletAddress != null) {
            body.put("walletAddress", walletAddress);
        }
        if (customMetadata != null) {
            body.put("customMetadata", customMetadata);
        }
        return body;
    }

    public static Builder builder(String tenantId) {
        return new Builder(tenantId);
    }

    public static final class Builder {
        private final String tenantId;
        private String email;
        private String walletAddress;
        private Map<String, Object> customMetadata;

        private Builder(String tenantId) {
            this.tenantId = tenantId;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder walletAddress(String walletAddress) {
            this.walletAddress = walletAddress;
            return this;
        }

        public Builder customMetadata(Map<String, Object> customMetadata) {
            this.customMetadata = customMetadata;
            return this;
        }

        public CreateUserInput build() {
            return new CreateUserInput(this);
        }
    }
}
