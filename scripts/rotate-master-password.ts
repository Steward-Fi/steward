#!/usr/bin/env bun
/**
 * Master password / KDF salt rotation tool.
 *
 * Decrypts every encrypted record with the OLD KeyStore and re-encrypts with
 * the NEW KeyStore. Pages 100 rows per transaction. Holds a pg advisory lock
 * for the duration so two runs cannot race.
 *
 * Env:
 *   STEWARD_MASTER_PASSWORD       OLD password (required)
 *   STEWARD_KDF_SALT              OLD salt (optional, dev fallback otherwise)
 *   STEWARD_MASTER_PASSWORD_NEW   NEW password (required)
 *   STEWARD_KDF_SALT_NEW          NEW salt (required)
 *   DATABASE_URL                  required
 *
 * Flags:
 *   --dry-run            decrypt only, no writes
 *   --table <name>       restrict to one table (encrypted_keys |
 *                        encrypted_chain_keys | secrets | accounts)
 *
 * On error mid-run: exits non-zero with a "ROLLBACK REQUIRED:" message that
 * names the table and the inclusive id range that was already re-encrypted.
 * See docs/security/rotation-runbook.md.
 */

import { writeAuditEvent } from "../packages/api/src/services/audit";
import { createDb, sql } from "../packages/db/src/index";
import { KeyStore } from "../packages/vault/src/keystore";

type TableName = "encrypted_keys" | "encrypted_chain_keys" | "secrets" | "accounts";
const ALL_TABLES: TableName[] = ["encrypted_keys", "encrypted_chain_keys", "secrets", "accounts"];

const BATCH = 100;
const LOCK_KEY_SQL = sql`hashtext('steward_rotation')::bigint`;

interface Args {
  dryRun: boolean;
  table?: TableName;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--table") {
      const t = argv[++i] as TableName;
      if (!ALL_TABLES.includes(t)) {
        throw new Error(`--table must be one of ${ALL_TABLES.join(", ")}`);
      }
      out.table = t;
    } else if (a.startsWith("--")) {
      throw new Error(`unknown flag: ${a}`);
    }
  }
  return out;
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

interface RotateResult {
  table: TableName;
  processed: number;
  firstId: string | null;
  lastId: string | null;
}

type Db = ReturnType<typeof createDb>["db"];

async function rotateEncryptedKeys(
  db: Db,
  oldKs: KeyStore,
  newKs: KeyStore,
  dryRun: boolean,
): Promise<RotateResult> {
  let processed = 0;
  let firstId: string | null = null;
  let lastId: string | null = null;
  let cursor = "";
  while (true) {
    const batchFirst = cursor;
    const batchLast = await db.transaction(async (tx) => {
      const rows = (await tx.execute(
        sql`SELECT agent_id, ciphertext, iv, tag, salt FROM encrypted_keys
            WHERE agent_id > ${batchFirst}
            ORDER BY agent_id ASC LIMIT ${BATCH}`,
      )) as Array<{
        agent_id: string;
        ciphertext: string;
        iv: string;
        tag: string;
        salt: string;
      }>;
      if (rows.length === 0) return null;
      for (const r of rows) {
        const pt = oldKs.decrypt(r);
        if (!dryRun) {
          const enc = newKs.encrypt(pt);
          await tx.execute(
            sql`UPDATE encrypted_keys SET ciphertext = ${enc.ciphertext},
                iv = ${enc.iv}, tag = ${enc.tag}, salt = ${enc.salt}
                WHERE agent_id = ${r.agent_id}`,
          );
        }
        if (firstId === null) firstId = r.agent_id;
        lastId = r.agent_id;
        processed += 1;
      }
      return rows[rows.length - 1].agent_id;
    });
    if (batchLast === null) break;
    cursor = batchLast;
  }
  return { table: "encrypted_keys", processed, firstId, lastId };
}

async function rotateEncryptedChainKeys(
  db: Db,
  oldKs: KeyStore,
  newKs: KeyStore,
  dryRun: boolean,
): Promise<RotateResult> {
  let processed = 0;
  let firstId: string | null = null;
  let lastId: string | null = null;
  let cursor = "00000000-0000-0000-0000-000000000000";
  while (true) {
    const batchFirst = cursor;
    const batchLast = await db.transaction(async (tx) => {
      const rows = (await tx.execute(
        sql`SELECT id, ciphertext, iv, tag, salt FROM encrypted_chain_keys
            WHERE id > ${batchFirst}::uuid
            ORDER BY id ASC LIMIT ${BATCH}`,
      )) as Array<{ id: string; ciphertext: string; iv: string; tag: string; salt: string }>;
      if (rows.length === 0) return null;
      for (const r of rows) {
        const pt = oldKs.decrypt(r);
        if (!dryRun) {
          const enc = newKs.encrypt(pt);
          await tx.execute(
            sql`UPDATE encrypted_chain_keys SET ciphertext = ${enc.ciphertext},
                iv = ${enc.iv}, tag = ${enc.tag}, salt = ${enc.salt}
                WHERE id = ${r.id}::uuid`,
          );
        }
        if (firstId === null) firstId = r.id;
        lastId = r.id;
        processed += 1;
      }
      return rows[rows.length - 1].id;
    });
    if (batchLast === null) break;
    cursor = batchLast;
  }
  return { table: "encrypted_chain_keys", processed, firstId, lastId };
}

async function rotateSecrets(
  db: Db,
  oldKs: KeyStore,
  newKs: KeyStore,
  dryRun: boolean,
): Promise<RotateResult> {
  let processed = 0;
  let firstId: string | null = null;
  let lastId: string | null = null;
  let cursor = "00000000-0000-0000-0000-000000000000";
  while (true) {
    const batchFirst = cursor;
    const batchLast = await db.transaction(async (tx) => {
      const rows = (await tx.execute(
        sql`SELECT id, ciphertext, iv, auth_tag, salt FROM secrets
            WHERE id > ${batchFirst}::uuid AND deleted_at IS NULL
            ORDER BY id ASC LIMIT ${BATCH}`,
      )) as Array<{ id: string; ciphertext: string; iv: string; auth_tag: string; salt: string }>;
      if (rows.length === 0) return null;
      for (const r of rows) {
        const pt = oldKs.decrypt({
          ciphertext: r.ciphertext,
          iv: r.iv,
          tag: r.auth_tag,
          salt: r.salt,
        });
        if (!dryRun) {
          const enc = newKs.encrypt(pt);
          await tx.execute(
            sql`UPDATE secrets SET ciphertext = ${enc.ciphertext},
                iv = ${enc.iv}, auth_tag = ${enc.tag}, salt = ${enc.salt}
                WHERE id = ${r.id}::uuid`,
          );
        }
        if (firstId === null) firstId = r.id;
        lastId = r.id;
        processed += 1;
      }
      return rows[rows.length - 1].id;
    });
    if (batchLast === null) break;
    cursor = batchLast;
  }
  return { table: "secrets", processed, firstId, lastId };
}

async function rotateAccounts(
  db: Db,
  oldKs: KeyStore,
  newKs: KeyStore,
  dryRun: boolean,
): Promise<RotateResult> {
  let processed = 0;
  let firstId: string | null = null;
  let lastId: string | null = null;
  let cursor = "00000000-0000-0000-0000-000000000000";
  while (true) {
    const batchFirst = cursor;
    const batchLast = await db.transaction(async (tx) => {
      const rows = (await tx.execute(
        sql`SELECT id,
              access_token_encrypted, access_token_iv, access_token_tag, access_token_salt,
              refresh_token_encrypted, refresh_token_iv, refresh_token_tag, refresh_token_salt
            FROM accounts
            WHERE id > ${batchFirst}::uuid
            ORDER BY id ASC LIMIT ${BATCH}`,
      )) as Array<{
        id: string;
        access_token_encrypted: string | null;
        access_token_iv: string | null;
        access_token_tag: string | null;
        access_token_salt: string | null;
        refresh_token_encrypted: string | null;
        refresh_token_iv: string | null;
        refresh_token_tag: string | null;
        refresh_token_salt: string | null;
      }>;
      if (rows.length === 0) return null;
      for (const r of rows) {
        const updates: Record<string, string> = {};
        if (
          r.access_token_encrypted &&
          r.access_token_iv &&
          r.access_token_tag &&
          r.access_token_salt
        ) {
          const pt = oldKs.decrypt({
            ciphertext: r.access_token_encrypted,
            iv: r.access_token_iv,
            tag: r.access_token_tag,
            salt: r.access_token_salt,
          });
          const enc = newKs.encrypt(pt);
          updates.access_token_encrypted = enc.ciphertext;
          updates.access_token_iv = enc.iv;
          updates.access_token_tag = enc.tag;
          updates.access_token_salt = enc.salt;
        }
        if (
          r.refresh_token_encrypted &&
          r.refresh_token_iv &&
          r.refresh_token_tag &&
          r.refresh_token_salt
        ) {
          const pt = oldKs.decrypt({
            ciphertext: r.refresh_token_encrypted,
            iv: r.refresh_token_iv,
            tag: r.refresh_token_tag,
            salt: r.refresh_token_salt,
          });
          const enc = newKs.encrypt(pt);
          updates.refresh_token_encrypted = enc.ciphertext;
          updates.refresh_token_iv = enc.iv;
          updates.refresh_token_tag = enc.tag;
          updates.refresh_token_salt = enc.salt;
        }
        if (!dryRun && Object.keys(updates).length > 0) {
          await tx.execute(
            sql`UPDATE accounts SET
                  access_token_encrypted = ${updates.access_token_encrypted ?? r.access_token_encrypted},
                  access_token_iv = ${updates.access_token_iv ?? r.access_token_iv},
                  access_token_tag = ${updates.access_token_tag ?? r.access_token_tag},
                  access_token_salt = ${updates.access_token_salt ?? r.access_token_salt},
                  refresh_token_encrypted = ${updates.refresh_token_encrypted ?? r.refresh_token_encrypted},
                  refresh_token_iv = ${updates.refresh_token_iv ?? r.refresh_token_iv},
                  refresh_token_tag = ${updates.refresh_token_tag ?? r.refresh_token_tag},
                  refresh_token_salt = ${updates.refresh_token_salt ?? r.refresh_token_salt}
                WHERE id = ${r.id}::uuid`,
          );
        }
        if (firstId === null) firstId = r.id;
        lastId = r.id;
        processed += 1;
      }
      return rows[rows.length - 1].id;
    });
    if (batchLast === null) break;
    cursor = batchLast;
  }
  return { table: "accounts", processed, firstId, lastId };
}

const ROTATORS: Record<
  TableName,
  (db: Db, oldKs: KeyStore, newKs: KeyStore, dryRun: boolean) => Promise<RotateResult>
> = {
  encrypted_keys: rotateEncryptedKeys,
  encrypted_chain_keys: rotateEncryptedChainKeys,
  secrets: rotateSecrets,
  accounts: rotateAccounts,
};

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const oldPw = requireEnv("STEWARD_MASTER_PASSWORD");
  const oldSalt = process.env.STEWARD_KDF_SALT;
  const newPw = requireEnv("STEWARD_MASTER_PASSWORD_NEW");
  const newSalt = requireEnv("STEWARD_KDF_SALT_NEW");

  if (newPw === oldPw && newSalt === oldSalt) {
    throw new Error("NEW password+salt are identical to OLD — nothing to rotate");
  }

  const oldKs = new KeyStore(oldPw, oldSalt);
  const newKs = new KeyStore(newPw, newSalt);

  const tables: TableName[] = args.table ? [args.table] : ALL_TABLES;
  const { client, db } = createDb();
  let current: TableName | null = null;
  let currentResult: RotateResult | null = null;
  try {
    const lockRows = (await db.execute(
      sql`SELECT pg_try_advisory_lock(${LOCK_KEY_SQL}) AS got`,
    )) as Array<{ got: boolean }>;
    if (!lockRows[0]?.got) {
      throw new Error("Another rotation run holds the steward_rotation advisory lock");
    }

    for (const table of tables) {
      current = table;
      currentResult = null;
      await writeAuditEvent({
        tenantId: "system",
        actorType: "system",
        action: "system.master_password_rotation.start",
        resourceType: "table",
        resourceId: table,
        metadata: { table, dryRun: args.dryRun },
      });

      const res = await ROTATORS[table](db, oldKs, newKs, args.dryRun);
      currentResult = res;

      await writeAuditEvent({
        tenantId: "system",
        actorType: "system",
        action: "system.master_password_rotation.complete",
        resourceType: "table",
        resourceId: table,
        metadata: {
          table,
          dryRun: args.dryRun,
          rowCount: res.processed,
          firstId: res.firstId,
          lastId: res.lastId,
        },
      });
      console.log(
        `[rotate] ${table}: ${res.processed} row(s)` +
          (res.processed > 0 ? ` [${res.firstId} .. ${res.lastId}]` : "") +
          (args.dryRun ? " (dry-run)" : ""),
      );
    }

    await db.execute(sql`SELECT pg_advisory_unlock(${LOCK_KEY_SQL})`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const range =
      currentResult && currentResult.firstId
        ? `${currentResult.firstId} .. ${currentResult.lastId} (${currentResult.processed} row(s))`
        : "unknown range — re-run dry-run to inspect";
    console.error(
      `ROLLBACK REQUIRED: rotation failed in table=${current ?? "<none>"} processed=${range}: ${msg}`,
    );
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
