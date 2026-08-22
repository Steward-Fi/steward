import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const migration = readFileSync(
  join(import.meta.dir, "..", "..", "drizzle", "0114_durable_wallet_claim_account_audit.sql"),
  "utf8",
);

describe("durable wallet claim and account provisioning migration", () => {
  it("pins unique source, target, token, and provisioned-authority ownership", () => {
    expect(migration).toContain(
      'CREATE TABLE IF NOT EXISTS "pregenerated_wallet_claim_lifecycles"',
    );
    expect(migration).toContain('"pregenerated_wallet_claim_token_uniq"');
    expect(migration).toContain('"pregenerated_wallet_claim_target_uniq"');
    expect(migration).toContain('"pregenerated_wallet_claim_source_uniq"');
    expect(migration).toContain(
      'CREATE TABLE IF NOT EXISTS "digital_asset_account_wallet_lifecycles"',
    );
    expect(migration).toContain('"digital_asset_account_wallet_lifecycle_wallet_uniq"');
    expect(migration).toContain('"owner_token" uuid NOT NULL');
    expect(migration).toContain('"lease_expires_at" timestamp with time zone NOT NULL');
  });

  it("stores progress and bindings but never plaintext or encrypted key material", () => {
    expect(migration).toContain('"solana_imported" boolean DEFAULT false NOT NULL');
    expect(migration).toContain('"evm_imported" boolean DEFAULT false NOT NULL');
    expect(migration).toContain('"target_adopted" boolean DEFAULT false NOT NULL');
    expect(migration).not.toMatch(/private[_ ]?key/i);
    expect(migration).not.toMatch(/ciphertext/i);
    expect(migration).not.toMatch(/mnemonic/i);
  });
});
