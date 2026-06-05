import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

function source(path: string): string {
  return readFileSync(join(import.meta.dir, "..", ...path.split("/")), "utf8");
}

function expectNoStoreBeforeReturn(src: string, marker: string, returnedSecret: string) {
  const start = src.indexOf(marker);
  expect(start).toBeGreaterThanOrEqual(0);
  const noStore = src.indexOf("setNoStoreHeaders(c)", start);
  const returned = src.indexOf(returnedSecret, start);
  expect(noStore).toBeGreaterThan(start);
  expect(returned).toBeGreaterThan(noStore);
}

describe("secret-bearing responses", () => {
  it("marks one-time app secrets and invitation tokens as non-cacheable", () => {
    expectNoStoreBeforeReturn(
      source("routes/tenant-config.ts"),
      'action: "tenant.app_client_secret.rotate"',
      "appSecret: generated.secret",
    );
    expectNoStoreBeforeReturn(
      source("routes/user.ts"),
      "sendTenantInvitation(email",
      "token, emailSent",
    );
    expectNoStoreBeforeReturn(
      source("routes/platform.ts"),
      "sendTenantInvitation(email",
      "token, emailSent",
    );
  });

  it("marks wallet signature responses as non-cacheable", () => {
    const vault = source("routes/vault.ts");
    for (const marker of [
      'action: "vault.message.signed"',
      'action: "vault.raw_hash.signed"',
      'action: "vault.raw_digest.signed"',
      'action: "vault.sign.typed_data"',
      'action: "vault.sign.user_operation"',
      'action: "vault.sign.authorization"',
      'action: "vault.sign.solana"',
    ]) {
      expectNoStoreBeforeReturn(vault, marker, "return c.json");
    }

    expectNoStoreBeforeReturn(
      source("routes/user.ts"),
      'action: "user.wallet.sign_message"',
      "signature, address",
    );
    const globalWallet = source("routes/global-wallet.ts");
    expectNoStoreBeforeReturn(globalWallet, 'method === "personal_sign"', "result: signature");
    expectNoStoreBeforeReturn(
      globalWallet,
      'method === "eth_signTypedData_v4"',
      "result: signature",
    );
  });

  it("marks MFA-gated audit and dashboard reads as non-cacheable", () => {
    expect(source("routes/audit.ts")).toContain("setNoStoreHeaders(c);");
    expectNoStoreBeforeReturn(
      source("routes/dashboard.ts"),
      "Dashboard data requires recent MFA verification",
      "AgentDashboardResponse",
    );
  });

  it("marks auth routes as non-cacheable before token responses can be returned", () => {
    const auth = source("routes/auth.ts");
    expect(auth).toContain("function setAuthNoStoreHeaders");
    const middleware = auth.indexOf('auth.use("*"');
    const header = auth.indexOf("setAuthNoStoreHeaders(c)", middleware);
    expect(middleware).toBeGreaterThanOrEqual(0);
    expect(header).toBeGreaterThan(middleware);
    for (const marker of [
      "buildAuthResponse",
      'auth.get("/identity-token"',
      'auth.post("/refresh"',
      'auth.post("/oauth/exchange"',
      'auth.post("/oauth/:provider/token"',
    ]) {
      expect(auth.indexOf(marker, middleware)).toBeGreaterThan(header);
    }
  });
});
