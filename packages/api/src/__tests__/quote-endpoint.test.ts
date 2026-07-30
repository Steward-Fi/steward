import { afterEach, describe, expect, test } from "bun:test";
import { quoteRoutes } from "../routes/quote";

const savedProvider = process.env.STEWARD_ATTESTATION_PROVIDER;
const savedAllow = process.env.STEWARD_ATTESTATION_NOOP_ALLOW;
const savedNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  restore("STEWARD_ATTESTATION_PROVIDER", savedProvider);
  restore("STEWARD_ATTESTATION_NOOP_ALLOW", savedAllow);
  restore("NODE_ENV", savedNodeEnv);
});

describe("GET /quote", () => {
  test("serves explicit dev quote scaffold without silently verifying", async () => {
    process.env.STEWARD_ATTESTATION_PROVIDER = "noop-dev";
    delete process.env.STEWARD_ATTESTATION_NOOP_ALLOW;
    process.env.NODE_ENV = "test";

    const response = await quoteRoutes.request("/?nonce=test");
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body.provider).toBe("noop-dev");
    expect(body.verified).toBe(false);
  });

  test("dev quote scaffold can be explicitly allowed outside production", async () => {
    process.env.STEWARD_ATTESTATION_PROVIDER = "noop-dev";
    process.env.STEWARD_ATTESTATION_NOOP_ALLOW = "true";
    process.env.NODE_ENV = "test";

    const response = await quoteRoutes.request("/");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.verified).toBe(true);
  });
});

function restore(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
