package com.steward.sdk;

import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class StewardTransportRequest {
    private final String method;
    private final URI uri;
    private final Map<String, List<String>> headers;
    private final byte[] body;
    private final Duration timeout;

    public StewardTransportRequest(String method, URI uri, Map<String, List<String>> headers, byte[] body, Duration timeout) {
        this.method = method;
        this.uri = uri;
        this.headers = Collections.unmodifiableMap(headers);
        this.body = body == null ? null : body.clone();
        this.timeout = timeout;
    }

    public String getMethod() {
        return method;
    }

    public URI getUri() {
        return uri;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public String getHeader(String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    public byte[] getBody() {
        return body == null ? null : body.clone();
    }

    public Duration getTimeout() {
        return timeout;
    }
}
