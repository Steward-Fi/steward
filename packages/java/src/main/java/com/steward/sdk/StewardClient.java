package com.steward.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class StewardClient {
    private static final List<String> SENSITIVE_PREFIXES = List.of(
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
        "/v1/condition_sets"
    );
    private static final List<String> MUTATING_METHODS = List.of("POST", "PUT", "PATCH", "DELETE");

    private final Config config;
    private final String baseUrl;
    private final StewardTransport transport;

    public StewardClient(Config config) {
        if (config == null || isBlank(config.baseUrl)) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        this.config = config;
        this.baseUrl = trimRight(config.baseUrl, "/");
        this.transport = config.transport == null ? new DefaultTransport(config.httpClient) : config.transport;
    }

    public StewardResponse request(String method, String path) {
        return request(RequestOptions.builder(method, path).build());
    }

    public StewardResponse request(RequestOptions options) {
        String method = options.method.toUpperCase();
        String path = canonicalPath(options.path);
        byte[] body = options.body == null ? null : Json.stringify(options.body).getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> headers = headers(path, method, body, options.headers, options.idempotencyKey);
        URI uri = URI.create(baseUrl + path + queryString(options.query));
        try {
            StewardTransportResponse response = transport.send(new StewardTransportRequest(method, uri, headers, body, config.timeout));
            return decodeResponse(response);
        } catch (IOException e) {
            throw new StewardApiException(e.getMessage(), 0, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StewardApiException(e.getMessage(), 0, null);
        }
    }

    public Object get(String path) {
        return request("GET", path).getData();
    }

    public Object get(String path, Map<String, ?> query) {
        return request(RequestOptions.builder("GET", path).query(query).build()).getData();
    }

    public Object post(String path, Object body) {
        return request(RequestOptions.builder("POST", path).body(body).build()).getData();
    }

    public Object patch(String path, Object body) {
        return request(RequestOptions.builder("PATCH", path).body(body).build()).getData();
    }

    public Object delete(String path) {
        return request("DELETE", path).getData();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> createUser(CreateUserInput input) {
        return (Map<String, Object>) post("/platform/users", input.toMap());
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> getUser(String userId) {
        return (Map<String, Object>) get("/platform/users/" + pathEscape(userId));
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> lookupUser(Map<String, ?> query) {
        return (Map<String, Object>) get("/platform/users/lookup", query);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> listUserPushSubscriptions() {
        return (Map<String, Object>) get("/user/me/push-subscriptions");
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> registerUserPushSubscription(PushSubscriptionInput input) {
        return (Map<String, Object>) post("/user/me/push-subscriptions", input.toMap());
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> revokeUserPushSubscription(String subscriptionId) {
        return (Map<String, Object>) delete("/user/me/push-subscriptions/" + pathEscape(subscriptionId));
    }

    private Map<String, List<String>> headers(String path, String method, byte[] body, Map<String, String> extra, String idempotencyKey) {
        Map<String, String> merged = new LinkedHashMap<>();
        merged.put("Content-Type", "application/json");
        merged.put("Accept", "application/json");
        if (extra != null) {
            merged.putAll(extra);
        }
        if (!isBlank(config.platformKey)) {
            merged.put("X-Steward-Platform-Key", config.platformKey);
        } else if (!isBlank(config.bearerToken)) {
            merged.put("Authorization", "Bearer " + config.bearerToken);
        } else if (!isBlank(config.appId) && !isBlank(config.appSecret)) {
            String auth = Base64.getEncoder().encodeToString((config.appId + ":" + config.appSecret).getBytes(StandardCharsets.UTF_8));
            merged.put("Authorization", "Basic " + auth);
            merged.put("X-Steward-App-Id", config.appId);
        } else if (!isBlank(config.apiKey)) {
            merged.put("X-Steward-Key", config.apiKey);
        }
        if (!isBlank(config.tenantId)) {
            merged.put("X-Steward-Tenant", config.tenantId);
        }

        if (!isBlank(config.requestSigningSecret) && isSensitiveMutation(path, method)) {
            String timestamp = merged.computeIfAbsent("X-Steward-Request-Timestamp", ignored -> Long.toString(config.clock.instant().getEpochSecond()));
            String idem = merged.computeIfAbsent("Idempotency-Key", ignored -> idempotencyKey == null ? config.idFactory.newId() : idempotencyKey);
            if (!isBlank(config.requestSigningKeyId)) {
                merged.putIfAbsent("X-Steward-Signing-Key-Id", config.requestSigningKeyId);
            }
            String bodyHash = sha256Hex(body == null ? new byte[0] : body);
            String canonical = String.join("\n", method.toUpperCase(), path, timestamp, idem, bodyHash);
            merged.put("X-Steward-Signature", "v1=" + hmacSha256Hex(config.requestSigningSecret, canonical));
        }

        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : merged.entrySet()) {
            headers.put(entry.getKey(), List.of(entry.getValue()));
        }
        return headers;
    }

    private StewardResponse decodeResponse(StewardTransportResponse response) {
        byte[] raw = response.getBody();
        if (raw.length == 0) {
            if (response.getStatus() >= 400) {
                throw new StewardApiException("Request failed with status " + response.getStatus(), response.getStatus(), null);
            }
            return new StewardResponse(response.getStatus(), null, response.getHeaders());
        }
        Object payload;
        try {
            payload = Json.parse(new String(raw, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new StewardApiException("Received invalid JSON from Steward API", response.getStatus(), null);
        }
        if (response.getStatus() >= 400 || (payload instanceof Map<?, ?> map && Boolean.FALSE.equals(map.get("ok")))) {
            String message = null;
            if (payload instanceof Map<?, ?> map) {
                Object error = map.get("error");
                message = error == null ? null : String.valueOf(error);
            }
            throw new StewardApiException(message == null ? "Request failed with status " + response.getStatus() : message, response.getStatus(), payload);
        }
        Object data = payload;
        if (payload instanceof Map<?, ?> map && map.containsKey("data")) {
            data = map.get("data");
        }
        return new StewardResponse(response.getStatus(), data, response.getHeaders());
    }

    private static boolean isSensitiveMutation(String path, String method) {
        if (!MUTATING_METHODS.contains(method.toUpperCase())) {
            return false;
        }
        for (String prefix : SENSITIVE_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String canonicalPath(String path) {
        return path.startsWith("/") ? path : "/" + path;
    }

    private static String queryString(Map<String, ?> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, ?> entry : query.entrySet()) {
            if (entry.getValue() != null) {
                parts.add(urlEncode(entry.getKey()) + "=" + urlEncode(String.valueOf(entry.getValue())));
            }
        }
        return parts.isEmpty() ? "" : "?" + String.join("&", parts);
    }

    private static String pathEscape(String value) {
        return urlEncode(value).replace("+", "%20");
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String trimRight(String value, String suffix) {
        while (value.endsWith(suffix)) {
            value = value.substring(0, value.length() - suffix.length());
        }
        return value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String sha256Hex(byte[] body) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return hex(digest.digest(body));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hmacSha256Hex(String secret, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return hex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            chars[i * 2] = alphabet[value >>> 4];
            chars[i * 2 + 1] = alphabet[value & 0x0f];
        }
        return new String(chars);
    }

    public static Config.Builder config(String baseUrl) {
        return Config.builder(baseUrl);
    }

    public static final class Config {
        private final String baseUrl;
        private final String apiKey;
        private final String bearerToken;
        private final String platformKey;
        private final String appId;
        private final String appSecret;
        private final String tenantId;
        private final String requestSigningSecret;
        private final String requestSigningKeyId;
        private final Duration timeout;
        private final StewardTransport transport;
        private final HttpClient httpClient;
        private final Clock clock;
        private final IdFactory idFactory;

        private Config(Builder builder) {
            this.baseUrl = builder.baseUrl;
            this.apiKey = builder.apiKey;
            this.bearerToken = builder.bearerToken;
            this.platformKey = builder.platformKey;
            this.appId = builder.appId;
            this.appSecret = builder.appSecret;
            this.tenantId = builder.tenantId;
            this.requestSigningSecret = builder.requestSigningSecret;
            this.requestSigningKeyId = builder.requestSigningKeyId;
            this.timeout = builder.timeout;
            this.transport = builder.transport;
            this.httpClient = builder.httpClient;
            this.clock = builder.clock;
            this.idFactory = builder.idFactory;
        }

        public static Builder builder(String baseUrl) {
            return new Builder(baseUrl);
        }

        public static final class Builder {
            private final String baseUrl;
            private String apiKey;
            private String bearerToken;
            private String platformKey;
            private String appId;
            private String appSecret;
            private String tenantId;
            private String requestSigningSecret;
            private String requestSigningKeyId;
            private Duration timeout = Duration.ofSeconds(30);
            private StewardTransport transport;
            private HttpClient httpClient;
            private Clock clock = Clock.systemUTC();
            private IdFactory idFactory = () -> UUID.randomUUID().toString();

            private Builder(String baseUrl) {
                this.baseUrl = baseUrl;
            }

            public Builder apiKey(String apiKey) {
                this.apiKey = apiKey;
                return this;
            }

            public Builder bearerToken(String bearerToken) {
                this.bearerToken = bearerToken;
                return this;
            }

            public Builder platformKey(String platformKey) {
                this.platformKey = platformKey;
                return this;
            }

            public Builder appCredentials(String appId, String appSecret) {
                this.appId = appId;
                this.appSecret = appSecret;
                return this;
            }

            public Builder tenantId(String tenantId) {
                this.tenantId = tenantId;
                return this;
            }

            public Builder requestSigningSecret(String requestSigningSecret) {
                this.requestSigningSecret = requestSigningSecret;
                return this;
            }

            public Builder requestSigningKeyId(String requestSigningKeyId) {
                this.requestSigningKeyId = requestSigningKeyId;
                return this;
            }

            public Builder timeout(Duration timeout) {
                this.timeout = timeout;
                return this;
            }

            public Builder transport(StewardTransport transport) {
                this.transport = transport;
                return this;
            }

            public Builder httpClient(HttpClient httpClient) {
                this.httpClient = httpClient;
                return this;
            }

            public Builder clock(Clock clock) {
                this.clock = clock;
                return this;
            }

            public Builder idFactory(IdFactory idFactory) {
                this.idFactory = idFactory;
                return this;
            }

            public Config build() {
                return new Config(this);
            }
        }
    }

    @FunctionalInterface
    public interface IdFactory {
        String newId();
    }

    public static final class RequestOptions {
        private final String method;
        private final String path;
        private final Object body;
        private final Map<String, ?> query;
        private final Map<String, String> headers;
        private final String idempotencyKey;

        private RequestOptions(Builder builder) {
            this.method = builder.method;
            this.path = builder.path;
            this.body = builder.body;
            this.query = builder.query;
            this.headers = builder.headers;
            this.idempotencyKey = builder.idempotencyKey;
        }

        public static Builder builder(String method, String path) {
            return new Builder(method, path);
        }

        public static final class Builder {
            private final String method;
            private final String path;
            private Object body;
            private Map<String, ?> query = Collections.emptyMap();
            private Map<String, String> headers = Collections.emptyMap();
            private String idempotencyKey;

            private Builder(String method, String path) {
                this.method = method;
                this.path = path;
            }

            public Builder body(Object body) {
                this.body = body;
                return this;
            }

            public Builder query(Map<String, ?> query) {
                this.query = query == null ? Collections.emptyMap() : query;
                return this;
            }

            public Builder headers(Map<String, String> headers) {
                this.headers = headers == null ? Collections.emptyMap() : headers;
                return this;
            }

            public Builder idempotencyKey(String idempotencyKey) {
                this.idempotencyKey = idempotencyKey;
                return this;
            }

            public RequestOptions build() {
                return new RequestOptions(this);
            }
        }
    }

    private static final class DefaultTransport implements StewardTransport {
        private final HttpClient httpClient;

        private DefaultTransport(HttpClient httpClient) {
            this.httpClient = httpClient == null ? HttpClient.newHttpClient() : httpClient;
        }

        @Override
        public StewardTransportResponse send(StewardTransportRequest request) throws IOException, InterruptedException {
            HttpRequest.Builder builder = HttpRequest.newBuilder(request.getUri()).timeout(request.getTimeout());
            for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
                for (String value : entry.getValue()) {
                    builder.header(entry.getKey(), value);
                }
            }
            byte[] body = request.getBody();
            HttpRequest.BodyPublisher publisher = body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body);
            HttpResponse<byte[]> response = httpClient.send(builder.method(request.getMethod(), publisher).build(), HttpResponse.BodyHandlers.ofByteArray());
            return new StewardTransportResponse(response.statusCode(), new HashMap<>(response.headers().map()), response.body());
        }
    }
}
