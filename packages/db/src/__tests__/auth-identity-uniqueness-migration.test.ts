import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";

function migration(name: string): string {
  return readFileSync(new URL(`../../drizzle/${name}`, import.meta.url), "utf8");
}

describe("auth identity migration fences", () => {
  it("keeps credential ids globally unique", () => {
    const authTables = migration("0008_auth_tables.sql");
    expect(authTables).toMatch(/credential_id\s+text\s+not null\s+unique/i);
  });

  it("keeps non-null wallet identities unique by chain and address", () => {
    const walletIdentity = migration("0032_user_wallet_identity_unique.sql");
    expect(walletIdentity).toContain("users_wallet_identity_unique_idx");
    expect(walletIdentity).toMatch(/unique index[\s\S]*wallet_chain[\s\S]*wallet_address/i);
    expect(walletIdentity).toMatch(/where wallet_address is not null/i);
  });
});
