package com.steward.sdk;

import java.util.List;
import java.util.Map;

public final class StewardResponse {
    private final int status;
    private final Object data;
    private final Map<String, List<String>> headers;

    public StewardResponse(int status, Object data, Map<String, List<String>> headers) {
        this.status = status;
        this.data = data;
        this.headers = headers;
    }

    public int getStatus() {
        return status;
    }

    public Object getData() {
        return data;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }
}
