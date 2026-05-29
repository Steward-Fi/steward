import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const proxyRoot = join(import.meta.dir, "..");
const authSource = readFileSync(join(proxyRoot, "middleware", "auth.ts"), "utf8");
const auditSource = readFileSync(join(proxyRoot, "middleware", "audit.ts"), "utf8");
const proxySource = readFileSync(join(proxyRoot, "handlers", "proxy.ts"), "utf8");

describe("proxy security hardening", () => {
  it("bounds signed request body hashing before signature verification", () => {
    expect(authSource).toContain("MAX_SIGNED_PROXY_BODY_BYTES");
    expect(authSource).toContain("boundedRequestBodyBuffer");
    expect(authSource).not.toContain("request.clone().arrayBuffer()");
    expect(authSource).toContain("Signed proxy request body is too large");
  });

  it("requires replay protection for every non-safe proxy method", () => {
    expect(proxySource).toContain('const SAFE_PROXY_METHODS = new Set(["GET", "HEAD", "OPTIONS"])');
    expect(proxySource).not.toContain("UNSAFE_PROXY_METHODS");
    expect(proxySource).toContain(
      'const requestType = signedRequest ? "signed proxy requests" : "mutating proxy requests"',
    );
    expect(proxySource).toContain("Idempotency-Key header is required for ${requestType}");
  });

  it("requires replay protection for signed safe proxy methods", () => {
    expect(proxySource).toContain(
      'const signedRequest = Boolean(requestHeader(c, "x-steward-signature"))',
    );
    expect(proxySource).toContain("SAFE_PROXY_METHODS.has(method.toUpperCase()) && !signedRequest");
    expect(proxySource).toContain("Idempotency-Key header is required for ${requestType}");
  });

  it("sets upstream timeout and response byte bounds", () => {
    expect(proxySource).toContain("PROXY_UPSTREAM_TIMEOUT_MS");
    expect(proxySource).toContain("MAX_PROXY_RESPONSE_BYTES");
    expect(proxySource).toContain("MAX_PROXY_STREAM_DURATION_MS");
    expect(proxySource).toContain("request.setTimeout");
    expect(proxySource).toContain("Proxy upstream response exceeded size limit");
    expect(proxySource).toContain("Proxy streaming response exceeded duration limit");
  });

  it("caps in-flight proxy requests per agent and tenant", () => {
    expect(proxySource).toContain("MAX_PROXY_IN_FLIGHT_PER_AGENT");
    expect(proxySource).toContain("MAX_PROXY_IN_FLIGHT_PER_TENANT");
    expect(proxySource).toContain("acquireProxySlot(agentId, tenantId)");
    expect(proxySource).toContain("releaseWhenBodyCloses");
    expect(proxySource).toContain("Too many in-flight proxy requests for agent");
  });

  it("fails closed when required credential-forwarding audit cannot be persisted", () => {
    expect(auditSource).toContain("export async function recordRequiredAudit");
    expect(auditSource).toContain("await insertAuditEntry(entry)");

    const slotIndex = proxySource.indexOf("const proxySlot = acquireProxySlot(agentId, tenantId)");
    const requiredAuditIndex = proxySource.indexOf("await recordRequiredAudit({");
    const decryptIndex = proxySource.indexOf(
      "credential = await decryptSecret(tenantId, route.secretId)",
    );
    const forwardIndex = proxySource.indexOf("response = await forwardProxyRequestForHandler(");

    expect(requiredAuditIndex).toBeGreaterThan(slotIndex);
    expect(requiredAuditIndex).toBeLessThan(decryptIndex);
    expect(requiredAuditIndex).toBeLessThan(forwardIndex);
    expect(proxySource).toContain("Proxy audit logging unavailable");
    expect(proxySource).toContain("releaseUnsafeProxyRequest(replayClaim)");
  });

  it("rejects malformed header credential injection without leaking replay or slot state", () => {
    expect(proxySource).toContain("Invalid credential header value");
    expect(proxySource).toContain("credential-injection-failed");
    expect(proxySource).toContain("Invalid credential injection configuration");

    const injectCall = proxySource.indexOf("injectCredential(outboundHeaders");
    const injectCatch = proxySource.indexOf("} catch {", injectCall);
    const injectionFailureAudit = proxySource.indexOf("credential-injection-failed", injectCatch);
    const forwardIndex = proxySource.indexOf("response = await forwardProxyRequestForHandler(");
    expect(injectCall).toBeGreaterThanOrEqual(0);
    expect(injectCatch).toBeGreaterThan(injectCall);
    expect(injectionFailureAudit).toBeGreaterThan(injectCatch);
    expect(injectCatch).toBeLessThan(forwardIndex);
    const cleanup = proxySource.slice(injectCatch, forwardIndex);
    expect(cleanup).toContain('credential = ""');
    expect(cleanup).toContain("releaseUnsafeProxyRequest(replayClaim)");
    expect(cleanup).toContain("proxySlot.release()");
  });

  it("fails closed for unsupported body credential injection", () => {
    expect(proxySource).toContain("Body credential injection is not supported");
    expect(proxySource).not.toContain("Body injection requested");
  });

  it("fails closed for query credential injection before decrypting or forwarding", () => {
    const routeCheck = proxySource.indexOf('route.injectAs === "query"');
    const decrypt = proxySource.indexOf(
      "credential = await decryptSecret(tenantId, route.secretId)",
    );
    const forward = proxySource.indexOf("response = await forwardProxyRequestForHandler(");
    expect(routeCheck).toBeGreaterThanOrEqual(0);
    expect(routeCheck).toBeLessThan(decrypt);
    expect(routeCheck).toBeLessThan(forward);
    expect(proxySource).toContain("query-credential-injection-disabled");
    expect(proxySource).toContain("Query credential injection is not supported");
  });

  it("strips method/path override and upstream idempotency headers", () => {
    for (const header of [
      '"idempotency-key"',
      '"x-http-method"',
      '"x-http-method-override"',
      '"x-method-override"',
      '"x-original-url"',
      '"x-rewrite-url"',
    ]) {
      expect(proxySource).toContain(header);
    }
  });

  it("blocks reflected header-injected credentials in upstream responses", () => {
    expect(proxySource).toContain("function responseHeaderReflectsCredential");
    expect(proxySource).toContain("function responseBodyCanReflectCredential");
    expect(proxySource).toContain("credential-reflected-in-response-header");
    expect(proxySource).toContain("credential-reflected-in-response-body");
    expect(proxySource).toContain("Upstream response reflected injected credential");

    const inject = proxySource.indexOf("let injectedCredentialValue");
    const forward = proxySource.indexOf("response = await forwardProxyRequestForHandler(");
    const reflectionCheck = proxySource.indexOf("responseHeaderReflectsCredential", forward);
    const responseReturn = proxySource.indexOf("return new Response(releasedResponseBody");
    expect(inject).toBeGreaterThanOrEqual(0);
    expect(reflectionCheck).toBeGreaterThan(forward);
    expect(reflectionCheck).toBeLessThan(responseReturn);
  });
});
