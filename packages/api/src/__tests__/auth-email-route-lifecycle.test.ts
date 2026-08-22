import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { PasskeyAuth } from "@stwd/auth";
import { authenticators, closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

process.env.NODE_ENV = "test";
process.env.EMAIL_PROVIDER = "mock";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_MASTER_PASSWORD = "email-route-lifecycle-master-password";
process.env.STEWARD_JWT_SECRET = "email-route-lifecycle-jwt-secret-with-enough-entropy";
process.env.STEWARD_AUDIT_HMAC_KEY = "email-route-lifecycle-audit-key-with-enough-entropy";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";

const TENANT_A = "email-lifecycle-a";
const TENANT_B = "email-lifecycle-b";
let authRoutes: typeof import("../routes/auth").authRoutes;
type TestJson = Record<string, unknown> & {
  data: Record<string, unknown>;
  token?: unknown;
  error?: unknown;
  challenge?: unknown;
};

async function post(path: string, body: Record<string, unknown>, tenantId?: string) {
  const response = await authRoutes.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(tenantId ? { "x-steward-tenant": tenantId } : {}),
    },
    body: JSON.stringify(body),
  });
  return { response, json: (await response.json()) as TestJson };
}

async function inbox(email: string) {
  const response = await authRoutes.request(`/test/inbox/${encodeURIComponent(email)}`);
  expect(response.status).toBe(200);
  return (await response.json()) as { text: string; token?: string };
}

function codeFrom(text: string): string {
  const code = text.match(/\b(\d{6})\b/)?.[1];
  if (!code) throw new Error("mock message did not include a six-digit code");
  return code;
}

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  ({ authRoutes } = await import("../routes/auth"));
  await getDb()
    .insert(tenants)
    .values([
      {
        id: TENANT_A,
        name: TENANT_A,
        apiKeyHash: "email-lifecycle-a-hash",
        ownerAddress: "0x0000000000000000000000000000000000000744",
      },
      {
        id: TENANT_B,
        name: TENANT_B,
        apiKeyHash: "email-lifecycle-b-hash",
        ownerAddress: "0x0000000000000000000000000000000000001744",
      },
    ]);
  await getDb()
    .insert(tenantConfigs)
    .values([
      { tenantId: TENANT_A, joinMode: "open" },
      { tenantId: TENANT_B, joinMode: "open" },
    ]);
});

afterAll(async () => closeDb());

describe("mounted email login-code and OTP grant lifecycle", () => {
  it("requires both opaque status credentials without exposing or burning login codes", async () => {
    const email = "status-lifecycle@example.test";
    const sent = await post("/email/send", { email, tenantId: TENANT_A });
    expect(sent.response.status).toBe(200);
    const credentials = sent.json.data as { challengeId: string; pollSecret: string };

    const missing = await post("/email/status", { challengeId: credentials.challengeId }, TENANT_A);
    expect(missing.response.status).toBe(400);
    const wrong = await post(
      "/email/status",
      { challengeId: credentials.challengeId, pollSecret: "wrong-poll-secret" },
      TENANT_A,
    );
    expect(wrong.response.status).toBe(200);
    expect(wrong.json.data.status).not.toBe("pending");
    const pending = await post("/email/status", credentials, TENANT_A);
    expect(pending.response.status).toBe(200);
    expect(pending.json.data.status).toBe("pending");

    const code = codeFrom((await inbox(email)).text);
    const wrongEmail = await post(
      "/email/code/verify",
      { email: "different@example.test", code, tenantId: TENANT_A },
      TENANT_A,
    );
    expect(wrongEmail.response.status).toBe(401);
    const wrongTenant = await post(
      "/email/code/verify",
      { email, code, tenantId: TENANT_B },
      TENANT_B,
    );
    expect(wrongTenant.response.status).toBe(401);
    const winner = await post("/email/code/verify", { email, code, tenantId: TENANT_A }, TENANT_A);
    expect(winner.response.status).toBe(200);
    expect(winner.json.token).toBeString();
    const replay = await post("/email/code/verify", { email, code, tenantId: TENANT_A }, TENANT_A);
    expect(replay.response.status).toBe(401);
  });

  it("allows exactly one concurrent companion-code winner", async () => {
    const email = "concurrent-code@example.test";
    const sent = await post("/email/send", { email, tenantId: TENANT_A });
    expect(sent.response.status).toBe(200);
    const code = codeFrom((await inbox(email)).text);
    const redeem = () => post("/email/code/verify", { email, code, tenantId: TENANT_A }, TENANT_A);
    const results = await Promise.all([redeem(), redeem()]);
    expect(results.map(({ response }) => response.status).sort()).toEqual([200, 401]);
    expect(results.filter(({ json }) => typeof json.token === "string")).toHaveLength(1);
  });

  it("keeps login codes and OTP grants purpose-bound", async () => {
    const email = "purpose-bound@example.test";
    expect((await post("/email/send", { email, tenantId: TENANT_A })).response.status).toBe(200);
    const loginCode = codeFrom((await inbox(email)).text);
    expect(
      (await post("/email/otp/verify", { email, code: loginCode, tenantId: TENANT_A }, TENANT_A))
        .response.status,
    ).toBe(401);
    expect(
      (await post("/email/code/verify", { email, code: loginCode, tenantId: TENANT_A }, TENANT_A))
        .response.status,
    ).toBe(200);

    const otpEmail = "purpose-bound-otp@example.test";
    expect(
      (await post("/email/otp/send", { email: otpEmail, tenantId: TENANT_A }, TENANT_A)).response
        .status,
    ).toBe(200);
    const otp = codeFrom((await inbox(otpEmail)).text);
    expect(
      (
        await post(
          "/email/code/verify",
          { email: otpEmail, code: otp, tenantId: TENANT_A },
          TENANT_A,
        )
      ).response.status,
    ).toBe(401);
    const verified = await post(
      "/email/otp/verify",
      { email: otpEmail, code: otp, tenantId: TENANT_A },
      TENANT_A,
    );
    expect(verified.response.status).toBe(200);
    expect(verified.json.data.emailGrant).toBeString();
  });

  it("peeks a verified-email grant for options and preserves it after failed WebAuthn", async () => {
    const email = "passkey-grant@example.test";
    expect(
      (await post("/email/otp/send", { email, tenantId: TENANT_A }, TENANT_A)).response.status,
    ).toBe(200);
    const otp = codeFrom((await inbox(email)).text);
    const verified = await post(
      "/email/otp/verify",
      { email, code: otp, tenantId: TENANT_A },
      TENANT_A,
    );
    const emailGrant = (verified.json.data as { emailGrant: string }).emailGrant;

    const options = await post(
      "/passkey/register/options",
      { email, emailGrant, tenantId: TENANT_A },
      TENANT_A,
    );
    expect(options.response.status).toBe(200);
    expect(options.json.challenge).toBeString();
    const failed = await post(
      "/passkey/register/verify",
      { email, emailGrant, tenantId: TENANT_A, response: { malformed: true } },
      TENANT_A,
    );
    expect(failed.response.status).toBe(400);
    expect(failed.json.error).toBe("Registration verification failed");
    const retryOptions = await post(
      "/passkey/register/options",
      { email, emailGrant, tenantId: TENANT_A },
      TENANT_A,
    );
    expect(retryOptions.response.status).toBe(200);
  });

  it("allows one concurrent passkey-registration grant winner and one authenticator write", async () => {
    const email = "passkey-grant-winner@example.test";
    expect(
      (await post("/email/otp/send", { email, tenantId: TENANT_A }, TENANT_A)).response.status,
    ).toBe(200);
    const otp = codeFrom((await inbox(email)).text);
    const verified = await post(
      "/email/otp/verify",
      { email, code: otp, tenantId: TENANT_A },
      TENANT_A,
    );
    const emailGrant = (verified.json.data as { emailGrant: string }).emailGrant;
    const registration = spyOn(PasskeyAuth.prototype, "verifyRegistration").mockImplementation(
      async (_userId, response) => ({
        verified: true,
        registrationInfo: {
          credential: {
            id: (response as { id: string }).id,
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
          },
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false,
          origin: "https://steward.fi",
          rpID: "steward.fi",
        },
      }),
    );
    const register = (credentialId: string) =>
      post(
        "/passkey/register/verify",
        {
          email,
          emailGrant,
          tenantId: TENANT_A,
          response: { id: credentialId, response: { transports: ["internal"] } },
        },
        TENANT_A,
      );
    const outcomes = await Promise.all([register("grant-winner-a"), register("grant-winner-b")]);
    expect(outcomes.map(({ response }) => response.status).sort()).toEqual([200, 401]);
    const stored = await getDb()
      .select({ id: authenticators.id })
      .from(authenticators)
      .where(
        eq(
          authenticators.userId,
          (await getDb().query.users.findFirst({
            where: (users, { eq }) => eq(users.email, email),
          }))!.id,
        ),
      );
    expect(stored).toHaveLength(1);
    registration.mockRestore();
  });

  it("fails closed without a shared OTP limiter and never mints a session", async () => {
    const email = "bounded-otp@example.test";
    expect(
      (await post("/email/otp/send", { email, tenantId: TENANT_A }, TENANT_A)).response.status,
    ).toBe(200);
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    process.env.NODE_ENV = "production";
    try {
      const blocked = await post(
        "/email/otp/verify",
        { email, code: "000000", tenantId: TENANT_A },
        TENANT_A,
      );
      expect(blocked.response.status).toBe(429);
      expect(blocked.json.token).toBeUndefined();
    } finally {
      process.env.NODE_ENV = "test";
      process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
    }
  });
});
