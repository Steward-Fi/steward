import { afterEach, describe, expect, test } from "bun:test";
import { quoteRoutes, redactQuoteEvidence } from "../routes/quote";

const savedProvider = process.env.STEWARD_ATTESTATION_PROVIDER;
const savedAllow = process.env.STEWARD_ATTESTATION_NOOP_ALLOW;
const savedAllowDevSecrets = process.env.STEWARD_ALLOW_DEV_SECRETS;
const savedNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  restore("STEWARD_ATTESTATION_PROVIDER", savedProvider);
  restore("STEWARD_ATTESTATION_NOOP_ALLOW", savedAllow);
  restore("STEWARD_ALLOW_DEV_SECRETS", savedAllowDevSecrets);
  restore("NODE_ENV", savedNodeEnv);
});

function configureNoop(allow: boolean, devSecrets: boolean) {
  process.env.STEWARD_ATTESTATION_PROVIDER = "noop-dev";
  if (allow) process.env.STEWARD_ATTESTATION_NOOP_ALLOW = "true";
  else delete process.env.STEWARD_ATTESTATION_NOOP_ALLOW;
  if (devSecrets) process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
  else delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  process.env.NODE_ENV = "test";
}

describe("GET /quote", () => {
  test("serves explicit dev quote scaffold without silently verifying", async () => {
    configureNoop(false, false);

    const response = await quoteRoutes.request("/?nonce=test", {
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body.provider).toBe("noop-dev");
    expect(body.verified).toBe(false);
  });

  test("dev quote scaffold can be explicitly allowed outside production with dual consent", async () => {
    configureNoop(true, true);

    const response = await quoteRoutes.request("/", {
      headers: { "x-forwarded-for": "10.0.0.2" },
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.verified).toBe(true);
  });

  // SEC-029: STEWARD_ATTESTATION_NOOP_ALLOW alone (no STEWARD_ALLOW_DEV_SECRETS
  // dual consent) must not produce vacuous-green quotes — the route fails
  // closed with a generic 503.
  test("noop allow without dev-secrets dual consent fails closed", async () => {
    configureNoop(true, false);

    const response = await quoteRoutes.request("/", {
      headers: { "x-forwarded-for": "10.0.0.3" },
    });
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body.error).toBe("attestation unavailable");
  });

  // SEC-085: an oversized nonce is a client error, not an unhandled 500.
  test("rejects nonces over 64 bytes with 400", async () => {
    configureNoop(false, false);

    const response = await quoteRoutes.request(`/?nonce=${"x".repeat(65)}`, {
      headers: { "x-forwarded-for": "10.0.0.4" },
    });
    expect(response.status).toBe(400);
  });

  // SEC-085: the public oracle is rate limited per client IP.
  test("rate limits anonymous callers", async () => {
    configureNoop(false, false);
    const headers = { "x-forwarded-for": "10.9.9.9" };

    let lastStatus = 0;
    for (let i = 0; i < 31; i++) {
      const response = await quoteRoutes.request("/", { headers });
      lastStatus = response.status;
    }
    expect(lastStatus).toBe(429);
  });
});

describe("redactQuoteEvidence (SEC-085)", () => {
  test("strips vm_config recursively but keeps quote material", () => {
    const redacted = redactQuoteEvidence({
      quote: "AA==",
      event_log: "[]",
      vm_config: '{"compose":"secret-env"}',
      info: { os_image_hash: "img", vm_config: "nested" },
    }) as Record<string, unknown>;
    expect(redacted.quote).toBe("AA==");
    expect(redacted.event_log).toBe("[]");
    expect(redacted.vm_config).toBeUndefined();
    expect((redacted.info as Record<string, unknown>).os_image_hash).toBe("img");
    expect((redacted.info as Record<string, unknown>).vm_config).toBeUndefined();
  });
});

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
