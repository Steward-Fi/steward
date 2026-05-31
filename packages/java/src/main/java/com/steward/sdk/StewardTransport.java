package com.steward.sdk;

import java.io.IOException;

@FunctionalInterface
public interface StewardTransport {
    StewardTransportResponse send(StewardTransportRequest request) throws IOException, InterruptedException;
}
