#!/usr/bin/env bun
/**
 * Secret-vault legacy-root re-encryption (SEC-164).
 *
 * Secrets written before KDF domain separation are encrypted under the legacy
 * (undomained) root — the same root the wallet signing-vault uses — and only
 * decrypt through SecretVault's compat fallback. This tool re-encrypts every
 * such row IN PLACE under the domain-separated `secret-vault` root (same
 * plaintext, same AAD context, fresh AEAD parameters), so the fallback can
 * then be disabled via STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK=false.
 *
 * This is NOT a password rotation: the master password and KDF salt do not
 * change. (scripts/rotate-master-password.ts already performs this same
 * legacy→domain re-encryption as a side effect of password rotation; use this
 * tool when you are NOT rotating the password.)
 *
 * Correctness requirements (mirrors SecretVault.migrateLegacyRootSecrets):
 *
 *   1. Complete inventory. EVERY secrets row is walked, including soft-deleted
 *      versions — their ciphertext remains at rest and must not be left
 *      dependent on the legacy root.
 *
 *   2. Idempotent and transactional. A complete no-write preflight classifies
 *      every row first. Write mode repeats the walk inside ONE database
 *      transaction guarded by an advisory lock; any failure rolls everything
 *      back. Rows already under the domain root are skipped, so reruns are
 *      safe.
 *
 *   3. No silent data loss. Rows that authenticate under NEITHER root are
 *      reported and left untouched; any such row aborts before write mode
 *      starts.
 *
 * Env:
 *   STEWARD_MASTER_PASSWORD   required (the CURRENT password — unchanged)
 *   STEWARD_KDF_SALT          optional (same value the runtime uses)
 *   DATABASE_URL              required
 *
 * Flags:
 *   --dry-run    classify and authenticate every row, write nothing
 *   --confirm    required for write mode
 *
 * Exit code is non-zero if any row cannot authenticate under either root.
 * After a clean write, rerun --dry-run: it must report migrated=0 failed=0.
 * Only then set STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK=false and restart
 * consumers. See docs/runbooks/key-rotation.md.
 */

import { createDb, sql } from "../packages/db/src/index";
import { type LegacyRootSecretMigration, SecretVault } from "../packages/vault/src/secret-vault";

const LOCK_KEY_SQL = sql`hashtext('steward_legacy_secret_root_migration')::bigint`;

export interface Args {
  dryRun: boolean;
  confirm: boolean;
}

export function parseArgs(argv: string[]): Args {
  const out: Args = { dryRun: false, confirm: false };
  for (const a of argv) {
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--confirm") out.confirm = true;
    else if (a.startsWith("--")) throw new Error(`unknown flag: ${a}`);
  }
  return out;
}

export function validateArgs(args: Args): void {
  if (!args.dryRun && !args.confirm) {
    throw new Error("write mode requires --confirm after a successful --dry-run");
  }
}

function summarize(res: LegacyRootSecretMigration, dryRun: boolean): string {
  const parts = [
    `scanned=${res.scanned}`,
    `migrated=${res.migrated}`,
    `already=${res.alreadyDomainSeparated}`,
    `failed=${res.failed.length}`,
  ];
  return `[migrate-legacy-root] secrets: ${parts.join(" ")}${dryRun ? " (dry-run)" : ""}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  validateArgs(args);

  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) throw new Error("STEWARD_MASTER_PASSWORD is required");

  const vault = new SecretVault(masterPassword);
  const { client, db } = createDb();

  try {
    // Complete no-write preflight before the first mutation: a wrong password
    // or one corrupt row must never produce a partially migrated table.
    const preflight = await vault.migrateLegacyRootSecrets({ dryRun: true, db });
    console.log(summarize(preflight, true));
    if (preflight.failed.length > 0) {
      throw new Error(
        `preflight failed for ${preflight.failed.length} secret row(s); no writes performed`,
      );
    }

    if (!args.dryRun) {
      // One transaction is the journal: any write error rolls every row back,
      // so an interrupted invocation can be rerun safely.
      await db.transaction(async (tx) => {
        // Transaction-scoped lock stays on the same connection and is released
        // on commit/rollback (session locks are unsafe on pooled clients).
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCK_KEY_SQL})`);
        const res = await vault.migrateLegacyRootSecrets({ db: tx });
        if (res.failed.length > 0) {
          throw new Error("secrets changed after preflight; transaction rolled back");
        }
        console.log(summarize(res, false));
      });
      console.log(
        "MIGRATION COMPLETE. Verify with a final --dry-run (expect migrated=0 failed=0), " +
          "then set STEWARD_SECRET_VAULT_LEGACY_ROOT_FALLBACK=false on every consumer and restart.",
      );
    }
  } catch (err) {
    console.error(`MIGRATION ABORTED: ${err instanceof Error ? err.message : err}`);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

// Only auto-run when invoked directly (not when imported by the test).
if (import.meta.main) {
  main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
