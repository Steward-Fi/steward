package com.steward.sdk;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class StewardTransportResponse {
    private final int status;
    private final Map<String, List<String>> headers;
    private final byte[] body;

    public StewardTransportResponse(int status, Map<String, List<String>> headers, byte[] body) {
        this.status = status;
        this.headers = Collections.unmodifiableMap(headers);
        this.body = body == null ? new byte[0] : body.clone();
    }

    public int getStatus() {
        return status;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public byte[] getBody() {
        return body.clone();
    }
}
