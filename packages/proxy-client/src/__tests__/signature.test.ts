/**
 * Golden-vector tests: pin this client's signer against the proxy's own signer.
 *
 * We import `createProxyAuthorizationSignature` directly from @stwd/proxy (the
 * exact function the proxy verifier uses to build its expected signature) and
 * assert our `signProxyRequest` produces byte-identical output for a spread of
 * inputs. If the proxy canonical form ever drifts, these fail loudly.
 */

import { describe, expect, test } from "bun:test";
import { createProxyAuthorizationSignature } from "@stwd/proxy/src/middleware/auth";
import { buildCanonicalRequest, signProxyRequest } from "../signature";

const SECRET = "golden-vector-signing-secret-with-enough-bytes";

const VECTORS: Array<{
  name: string;
  input: Parameters<typeof signProxyRequest>[0];
}> = [
  {
    name: "GET no body, timestamp only",
    input: {
      method: "GET",
      url: "https://proxy.test/openai/v1/models",
      tenantId: "tenant-1",
      agentId: "agent-1",
      timestamp: "1751000000",
    },
  },
  {
    name: "POST json body + idempotency key",
    input: {
      method: "POST",
      url: "https://proxy.test/openai/v1/chat/completions",
      tenantId: "tenant-abc",
      agentId: "agent-xyz",
      timestamp: "1751000123",
      idempotencyKey: "11111111-2222-3333-4444-555555555555",
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    },
  },
  {
    name: "PATCH with query string + expiresAt",
    input: {
      method: "patch",
      url: "https://proxy.test/proxy/api.openai.com/v1/x?foo=bar&baz=1",
      tenantId: "t",
      agentId: "a",
      expiresAt: "1751000999",
      idempotencyKey: "abc",
      body: "raw-string-body",
    },
  },
  {
    name: "relative url (path only)",
    input: {
      method: "POST",
      url: "/openai/v1/chat/completions",
      tenantId: "tenant-1",
      agentId: "agent-1",
      timestamp: "1751000000",
      body: "{}",
    },
  },
];

describe("proxy-client signer golden vectors", () => {
  for (const vector of VECTORS) {
    test(`matches @stwd/proxy signer: ${vector.name}`, async () => {
      const ours = await signProxyRequest(vector.input, SECRET);
      const theirs = await createProxyAuthorizationSignature(vector.input, SECRET);
      expect(ours).toBe(theirs);
    });
  }

  test("canonical form is deterministic and version-tagged", async () => {
    const canonical = await buildCanonicalRequest({
      method: "GET",
      url: "https://proxy.test/openai/v1/models",
      tenantId: "tenant-1",
      agentId: "agent-1",
      timestamp: "1751000000",
    });
    const lines = canonical.split("\n");
    expect(lines[0]).toBe("steward-proxy-request-signature-v1");
    expect(lines[1]).toBe("GET");
    expect(lines[2]).toBe("/openai/v1/models");
    expect(lines[3]).toBe("tenant-1");
    expect(lines[4]).toBe("agent-1");
    expect(lines[5]).toBe("1751000000");
    // empty expiresAt + empty idempotency-key
    expect(lines[6]).toBe("");
    expect(lines[7]).toBe("");
    // sha256("") for empty body
    expect(lines[8]).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  test("signature has v1= prefix and 64-hex body", async () => {
    const sig = await signProxyRequest(
      {
        method: "GET",
        url: "/openai/v1/models",
        tenantId: "t",
        agentId: "a",
        timestamp: "1751000000",
      },
      SECRET,
    );
    expect(sig).toMatch(/^v1=[0-9a-f]{64}$/);
  });
});
