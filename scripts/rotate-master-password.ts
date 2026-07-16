#!/usr/bin/env bun
/**
 * Master password / KDF salt rotation tool.
 *
 * Re-encrypts every at-rest secret from the OLD KeyStore(s) to the NEW
 * KeyStore(s). This is an incident-response control: after a suspected master-
 * password or KDF-salt compromise an operator rotates every ciphertext to a
 * fresh root.
 *
 * Correctness requirements this tool MUST honour (see
 * docs/security/rotation-runbook.md and the encrypt sites it mirrors):
 *
 *   1. AAD + KDF-domain fidelity. Production ciphertext is bound to an AES-GCM
 *      AAD context AND (for secrets) a domain-separated scrypt root. Decrypting
 *      with the wrong context/domain fails the GCM auth-tag check, so this tool
 *      reconstructs, per row, the exact context + domain the encryptor used:
 *        - encrypted_keys / encrypted_chain_keys (wallet signing keys):
 *          signing-vault root (no KDF domain, matches Vault) + context
 *          { tenantId, agentId, chainFamily, venue }. The legacy encrypted_keys
 *          ciphertext is byte-identical to the NULL-venue encrypted_chain_keys
 *          row for the same agent, and its chainFamily AAD is whatever chainType
 *          was imported (evm OR solana), so we try candidate contexts and accept
 *          the one whose auth tag verifies (a wrong AAD cannot forge a plaintext).
 *        - secrets: secret-vault domain root + context { tenantId, name,
 *          version }, with a legacy (undomained) root fallback that mirrors
 *          SecretVault.decryptSecret.
 *        - accounts (OAuth provider tokens): legacy contextless/undomained root
 *          (matches encryptOAuthProviderTokens in packages/api auth.ts).
 *
 *   2. Idempotent and transactional. Every inventory class is authenticated in
 *      a complete no-write preflight. Write mode repeats that preflight, then
 *      updates all classes in one database transaction. Any failure rolls back
 *      all writes. Rows already under the NEW root are skipped.
 *
 *   3. No silent data loss. secrets rotation includes soft-deleted versions
 *      (deleted_at IS NOT NULL): SecretVault soft-deletes prior versions rather
 *      than purging their ciphertext, so skipping them would make that history
 *      permanently undecryptable once the old password is decommissioned.
 *
 * Env:
 *   STEWARD_MASTER_PASSWORD       OLD password (required)
 *   STEWARD_KDF_SALT              OLD salt (optional, dev fallback otherwise)
 *   STEWARD_MASTER_PASSWORD_NEW   NEW password (required)
 *   STEWARD_KDF_SALT_NEW          NEW salt (required)
 *   DATABASE_URL                  required
 *
 * Flags:
 *   --dry-run            decrypt only, no writes (still verifies every row)
 *   --confirm            required for complete-inventory write mode
 *   --table <name>       restrict dry-run diagnostics to one inventory class
 *
 * Exit code is non-zero if any row cannot authenticate under OLD or NEW. Write
 * mode never starts when preflight finds such a row.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { writeAuditEvent } from "../packages/api/src/services/audit";
import {
  accounts,
  agents,
  createDb,
  encryptedChainKeys,
  encryptedKeys,
  eq,
  getDb,
  gt,
  pendingProxyRequests,
  secrets as secretsTable,
  sql,
  tenantConfigs,
  tenantRequestSigningKeys,
  webhookConfigs,
} from "../packages/db/src/index";
import { type EncryptedKey, KeyStore, type KeyStoreDomain } from "../packages/vault/src/keystore";
import type { KeystoreContext } from "../packages/vault/src/keystore-backend";

type Db = ReturnType<typeof createDb>["db"] | ReturnType<typeof getDb>;

export type TableName =
  | "encrypted_keys"
  | "encrypted_chain_keys"
  | "secrets"
  | "accounts"
  | "tenant_request_signing_keys"
  | "pending_proxy_requests"
  | "tenant_email_configs"
  | "webhook_configs";
export const ALL_TABLES: TableName[] = [
  "encrypted_keys",
  "encrypted_chain_keys",
  "secrets",
  "accounts",
  "tenant_request_signing_keys",
  "pending_proxy_requests",
  "tenant_email_configs",
  "webhook_configs",
];

const BATCH = 100;
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";
const LOCK_KEY_SQL = sql`hashtext('steward_rotation')::bigint`;

export interface Args {
  dryRun: boolean;
  confirm: boolean;
  table?: TableName;
}

export function parseArgs(argv: string[]): Args {
  const out: Args = { dryRun: false, confirm: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--confirm") out.confirm = true;
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

export function validateArgs(args: Args): void {
  if (!args.dryRun && !args.confirm) {
    throw new Error("write mode requires --confirm after a successful --dry-run");
  }
  if (!args.dryRun && args.table) {
    throw new Error("write mode cannot use --table; complete inventory rotation is mandatory");
  }
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

export interface RotateResult {
  table: TableName;
  /** Rows newly re-encrypted under the NEW keystore in this run. */
  rotated: number;
  /** Rows that already verified under the NEW keystore (idempotent skips). */
  alreadyRotated: number;
  /**
   * Row identifiers that could not be decrypted under OLD or NEW. Recorded and
   * skipped so the rest of the table still rotates; the run exits non-zero.
   */
  failed: string[];
  firstId: string | null;
  lastId: string | null;
}

function emptyResult(table: TableName): RotateResult {
  return {
    table,
    rotated: 0,
    alreadyRotated: 0,
    failed: [],
    firstId: null,
    lastId: null,
  };
}

/**
 * A pair of keystores (old + new) for one logical encryption root, plus the
 * candidate AAD contexts a given row may have been encrypted under. The first
 * context whose auth tag verifies is the correct one; AES-GCM guarantees a
 * wrong AAD cannot produce a valid plaintext, so try-and-accept is safe.
 */
interface RootKeystores {
  old: KeyStore;
  new: KeyStore;
}

/**
 * Decrypt `enc` by trying each candidate context in order and returning the
 * plaintext from the first one that authenticates. `ks.decrypt` throws on an
 * auth-tag mismatch, so we catch and advance. Returns the plaintext AND the
 * context that worked (so re-encryption uses the identical context).
 */
function decryptWithCandidates(
  ks: KeyStore,
  enc: EncryptedKey,
  candidates: Array<KeystoreContext | undefined>,
): { plaintext: string; context: KeystoreContext | undefined } {
  let lastError: unknown;
  for (const context of candidates) {
    try {
      const plaintext = ks.decrypt(enc, context);
      return { plaintext, context };
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error("decrypt failed under every candidate context");
}

/**
 * Resolve a single row: skip if already under NEW, otherwise decrypt under OLD
 * and re-encrypt under NEW with the matching context.
 *
 * Returns:
 *   - { status: "already" }  the NEW keystore already verifies this row
 *   - { status: "rotated", enc }  freshly re-encrypted ciphertext to persist
 *   - throws  if neither OLD nor NEW can decrypt (caller records + continues)
 */
function resolveRow(
  roots: RootKeystores,
  enc: EncryptedKey,
  candidates: Array<KeystoreContext | undefined>,
): { status: "already" } | { status: "rotated"; enc: EncryptedKey } {
  // Idempotency / resume: if the NEW keystore already authenticates this row,
  // it was rotated by a previous (possibly aborted) run. No-op.
  try {
    decryptWithCandidates(roots.new, enc, candidates);
    return { status: "already" };
  } catch {
    // Not yet rotated (expected for the common path), fall through to OLD.
  }

  const { plaintext, context } = decryptWithCandidates(roots.old, enc, candidates);
  const reEncrypted = roots.new.encrypt(plaintext, context);
  return { status: "rotated", enc: reEncrypted };
}

// ───────────────────────────── encrypted_keys ────────────────────────────────
// Legacy single-key table. The ciphertext is identical to the NULL-venue
// encrypted_chain_keys row, and its AAD chainFamily is whatever chainType was
// imported. Reconstruct context from the joined agent row: prefer the chain
// family implied by the agent's wallet address, then fall back to the other
// family (covers Solana keys imported into the EVM-named legacy table).
export async function rotateEncryptedKeys(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("encrypted_keys");
  let cursor = "";
  while (true) {
    const rows = await db
      .select({
        agentId: encryptedKeys.agentId,
        ciphertext: encryptedKeys.ciphertext,
        iv: encryptedKeys.iv,
        tag: encryptedKeys.tag,
        salt: encryptedKeys.salt,
        tenantId: agents.tenantId,
        walletAddress: agents.walletAddress,
      })
      .from(encryptedKeys)
      .innerJoin(agents, eq(encryptedKeys.agentId, agents.id))
      .where(gt(encryptedKeys.agentId, cursor))
      .orderBy(encryptedKeys.agentId)
      .limit(BATCH);
    if (rows.length === 0) break;

    for (const r of rows) {
      const enc: EncryptedKey = {
        ciphertext: r.ciphertext,
        iv: r.iv,
        tag: r.tag,
        salt: r.salt,
      };
      const primaryFamily = r.walletAddress.startsWith("0x") ? "evm" : "solana";
      const otherFamily = primaryFamily === "evm" ? "solana" : "evm";
      const candidates: KeystoreContext[] = [
        { tenantId: r.tenantId, agentId: r.agentId, chainFamily: primaryFamily, venue: null },
        { tenantId: r.tenantId, agentId: r.agentId, chainFamily: otherFamily, venue: null },
      ];
      if (result.firstId === null) result.firstId = r.agentId;
      result.lastId = r.agentId;
      try {
        const resolved = resolveRow(roots, enc, candidates);
        if (resolved.status === "already") {
          result.alreadyRotated += 1;
        } else {
          if (!dryRun) {
            await db
              .update(encryptedKeys)
              .set({
                ciphertext: resolved.enc.ciphertext,
                iv: resolved.enc.iv,
                tag: resolved.enc.tag,
                salt: resolved.enc.salt,
              })
              .where(eq(encryptedKeys.agentId, r.agentId));
          }
          result.rotated += 1;
        }
      } catch (err) {
        result.failed.push(`agent_id=${r.agentId}: ${errMsg(err)}`);
      }
    }
    cursor = rows[rows.length - 1].agentId;
    if (rows.length < BATCH) break;
  }
  return result;
}

// ─────────────────────────── encrypted_chain_keys ────────────────────────────
// Multi-chain / venue-scoped keys. Context is read directly from the row:
// { tenantId (via agent join), agentId, chainFamily, venue }.
export async function rotateEncryptedChainKeys(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("encrypted_chain_keys");
  let cursor = ZERO_UUID;
  while (true) {
    const rows = await db
      .select({
        id: encryptedChainKeys.id,
        agentId: encryptedChainKeys.agentId,
        chainFamily: encryptedChainKeys.chainFamily,
        venue: encryptedChainKeys.venue,
        ciphertext: encryptedChainKeys.ciphertext,
        iv: encryptedChainKeys.iv,
        tag: encryptedChainKeys.tag,
        salt: encryptedChainKeys.salt,
        tenantId: agents.tenantId,
      })
      .from(encryptedChainKeys)
      .innerJoin(agents, eq(encryptedChainKeys.agentId, agents.id))
      .where(gt(encryptedChainKeys.id, cursor))
      .orderBy(encryptedChainKeys.id)
      .limit(BATCH);
    if (rows.length === 0) break;

    for (const r of rows) {
      const enc: EncryptedKey = {
        ciphertext: r.ciphertext,
        iv: r.iv,
        tag: r.tag,
        salt: r.salt,
      };
      // Mirror the encrypt site exactly: venue is passed through as-is (null on
      // legacy rows). Also try the alternate venue normalization in case a row
      // was written with `venue: undefined` vs `null` (aadForContext maps both
      // to "" so this is belt-and-suspenders, not a correctness gap).
      const candidates: KeystoreContext[] = [
        {
          tenantId: r.tenantId,
          agentId: r.agentId,
          chainFamily: r.chainFamily,
          venue: r.venue ?? null,
        },
      ];
      if (result.firstId === null) result.firstId = r.id;
      result.lastId = r.id;
      try {
        const resolved = resolveRow(roots, enc, candidates);
        if (resolved.status === "already") {
          result.alreadyRotated += 1;
        } else {
          if (!dryRun) {
            await db
              .update(encryptedChainKeys)
              .set({
                ciphertext: resolved.enc.ciphertext,
                iv: resolved.enc.iv,
                tag: resolved.enc.tag,
                salt: resolved.enc.salt,
              })
              .where(eq(encryptedChainKeys.id, r.id));
          }
          result.rotated += 1;
        }
      } catch (err) {
        result.failed.push(`id=${r.id} agent_id=${r.agentId}: ${errMsg(err)}`);
      }
    }
    cursor = rows[rows.length - 1].id;
    if (rows.length < BATCH) break;
  }
  return result;
}

// ───────────────────────────────── secrets ───────────────────────────────────
// Secret-vault domain root + context { tenantId, name, version }. Includes
// soft-deleted versions so prior-version ciphertext is not orphaned under the
// old password. Falls back to the legacy (undomained) root for secrets written
// before domain separation, mirrors SecretVault.decryptSecret.
export async function rotateSecrets(
  db: Db,
  domainRoots: RootKeystores,
  legacyRoots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("secrets");
  let cursor = ZERO_UUID;
  while (true) {
    // NOTE: no `deleted_at IS NULL` filter, soft-deleted versions must rotate
    // too, otherwise they become permanently undecryptable after the old
    // password is decommissioned.
    const rows = await db
      .select({
        id: secretsTable.id,
        tenantId: secretsTable.tenantId,
        name: secretsTable.name,
        version: secretsTable.version,
        ciphertext: secretsTable.ciphertext,
        iv: secretsTable.iv,
        authTag: secretsTable.authTag,
        salt: secretsTable.salt,
      })
      .from(secretsTable)
      .where(gt(secretsTable.id, cursor))
      .orderBy(secretsTable.id)
      .limit(BATCH);
    if (rows.length === 0) break;

    for (const r of rows) {
      const enc: EncryptedKey = {
        ciphertext: r.ciphertext,
        iv: r.iv,
        tag: r.authTag,
        salt: r.salt,
      };
      const context: KeystoreContext = {
        tenantId: r.tenantId,
        name: r.name,
        version: r.version,
      };
      if (result.firstId === null) result.firstId = r.id;
      result.lastId = r.id;
      try {
        const resolved = resolveSecretRow(domainRoots, legacyRoots, enc, context);
        if (resolved.status === "already") {
          result.alreadyRotated += 1;
        } else {
          if (!dryRun) {
            await db
              .update(secretsTable)
              .set({
                ciphertext: resolved.enc.ciphertext,
                iv: resolved.enc.iv,
                authTag: resolved.enc.tag,
                salt: resolved.enc.salt,
              })
              .where(eq(secretsTable.id, r.id));
          }
          result.rotated += 1;
        }
      } catch (err) {
        result.failed.push(`id=${r.id}: ${errMsg(err)}`);
      }
    }
    cursor = rows[rows.length - 1].id;
    if (rows.length < BATCH) break;
  }
  return result;
}

/**
 * Secret-specific row resolver. Always RE-ENCRYPTS under the NEW domain
 * (secret-vault) root so post-rotation reads succeed via SecretVault's primary
 * (domain) path. Decryption tries, in order:
 *   1. NEW domain root  → already rotated (idempotent skip)
 *   2. OLD domain root  → standard rotate
 *   3. OLD legacy root  → pre-domain-separation secret; rotate it INTO the new
 *      domain root so it stops depending on the legacy fallback.
 */
function resolveSecretRow(
  domainRoots: RootKeystores,
  legacyRoots: RootKeystores,
  enc: EncryptedKey,
  context: KeystoreContext,
): { status: "already" } | { status: "rotated"; enc: EncryptedKey } {
  // Already rotated? NEW domain root authenticates.
  try {
    domainRoots.new.decrypt(enc, context);
    return { status: "already" };
  } catch {
    // fall through
  }

  let plaintext: string;
  try {
    plaintext = domainRoots.old.decrypt(enc, context);
  } catch {
    // Pre-domain-separation secret: stored under the legacy (undomained) root.
    plaintext = legacyRoots.old.decrypt(enc, context);
  }
  const reEncrypted = domainRoots.new.encrypt(plaintext, context);
  return { status: "rotated", enc: reEncrypted };
}

// ───────────────────────────────── accounts ──────────────────────────────────
// OAuth provider access/refresh tokens. Encrypted with the legacy contextless,
// undomained root (matches encryptOAuthProviderTokens in packages/api auth.ts),
// so candidates = [undefined] (no AAD).
export async function rotateAccounts(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("accounts");
  const noContext: Array<KeystoreContext | undefined> = [undefined];
  let cursor = ZERO_UUID;
  while (true) {
    const rows = await db
      .select({
        id: accounts.id,
        accessTokenEncrypted: accounts.accessTokenEncrypted,
        accessTokenIv: accounts.accessTokenIv,
        accessTokenTag: accounts.accessTokenTag,
        accessTokenSalt: accounts.accessTokenSalt,
        refreshTokenEncrypted: accounts.refreshTokenEncrypted,
        refreshTokenIv: accounts.refreshTokenIv,
        refreshTokenTag: accounts.refreshTokenTag,
        refreshTokenSalt: accounts.refreshTokenSalt,
      })
      .from(accounts)
      .where(gt(accounts.id, cursor))
      .orderBy(accounts.id)
      .limit(BATCH);
    if (rows.length === 0) break;

    for (const r of rows) {
      if (result.firstId === null) result.firstId = r.id;
      result.lastId = r.id;

      const update: Partial<{
        accessTokenEncrypted: string;
        accessTokenIv: string;
        accessTokenTag: string;
        accessTokenSalt: string;
        refreshTokenEncrypted: string;
        refreshTokenIv: string;
        refreshTokenTag: string;
        refreshTokenSalt: string;
      }> = {};
      let rowFailed = false;
      let rowRotated = false;
      let rowAlready = false;

      const access = pickToken(
        r.accessTokenEncrypted,
        r.accessTokenIv,
        r.accessTokenTag,
        r.accessTokenSalt,
      );
      if (access) {
        try {
          const resolved = resolveRow(roots, access, noContext);
          if (resolved.status === "rotated") {
            update.accessTokenEncrypted = resolved.enc.ciphertext;
            update.accessTokenIv = resolved.enc.iv;
            update.accessTokenTag = resolved.enc.tag;
            update.accessTokenSalt = resolved.enc.salt;
            rowRotated = true;
          } else {
            rowAlready = true;
          }
        } catch (err) {
          rowFailed = true;
          result.failed.push(`id=${r.id} access_token: ${errMsg(err)}`);
        }
      }

      const refresh = pickToken(
        r.refreshTokenEncrypted,
        r.refreshTokenIv,
        r.refreshTokenTag,
        r.refreshTokenSalt,
      );
      if (refresh) {
        try {
          const resolved = resolveRow(roots, refresh, noContext);
          if (resolved.status === "rotated") {
            update.refreshTokenEncrypted = resolved.enc.ciphertext;
            update.refreshTokenIv = resolved.enc.iv;
            update.refreshTokenTag = resolved.enc.tag;
            update.refreshTokenSalt = resolved.enc.salt;
            rowRotated = true;
          } else {
            rowAlready = true;
          }
        } catch (err) {
          rowFailed = true;
          result.failed.push(`id=${r.id} refresh_token: ${errMsg(err)}`);
        }
      }

      if (!dryRun && Object.keys(update).length > 0) {
        await db.update(accounts).set(update).where(eq(accounts.id, r.id));
      }
      if (rowRotated) result.rotated += 1;
      else if (rowAlready && !rowFailed) result.alreadyRotated += 1;
    }
    cursor = rows[rows.length - 1].id;
    if (rows.length < BATCH) break;
  }
  return result;
}

function pickToken(
  ciphertext: string | null,
  iv: string | null,
  tag: string | null,
  salt: string | null,
): EncryptedKey | null {
  if (!ciphertext || !iv || !tag || !salt) return null;
  return { ciphertext, iv, tag, salt };
}

// Request-signing roots are secret-vault-domain ciphertext with stable AAD.
export async function rotateTenantRequestSigningKeys(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("tenant_request_signing_keys");
  const rows = await db
    .select()
    .from(tenantRequestSigningKeys)
    .orderBy(tenantRequestSigningKeys.id);
  for (const row of rows) {
    if (result.firstId === null) result.firstId = row.id;
    result.lastId = row.id;
    try {
      const resolved = resolveRow(
        roots,
        {
          ciphertext: row.secretCiphertext,
          iv: row.secretIv,
          tag: row.secretAuthTag,
          salt: row.secretSalt,
        },
        [{ tenantId: row.tenantId, name: `request-signing-key:${row.id}`, version: 1 }],
      );
      if (resolved.status === "already") result.alreadyRotated += 1;
      else {
        if (!dryRun) {
          await db
            .update(tenantRequestSigningKeys)
            .set({
              secretCiphertext: resolved.enc.ciphertext,
              secretIv: resolved.enc.iv,
              secretAuthTag: resolved.enc.tag,
              secretSalt: resolved.enc.salt,
            })
            .where(eq(tenantRequestSigningKeys.id, row.id));
        }
        result.rotated += 1;
      }
    } catch {
      result.failed.push(`id=${row.id}: authentication failed`);
    }
  }
  return result;
}

// Pending approval bodies are short-lived but must remain decryptable across a
// planned cutover. The request digest is part of their production AAD.
export async function rotatePendingProxyRequests(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("pending_proxy_requests");
  const rows = await db.select().from(pendingProxyRequests).orderBy(pendingProxyRequests.id);
  for (const row of rows) {
    if (result.firstId === null) result.firstId = row.id;
    result.lastId = row.id;
    try {
      const resolved = resolveRow(
        roots,
        {
          ciphertext: row.bodyCiphertext,
          iv: row.bodyIv,
          tag: row.bodyAuthTag,
          salt: row.bodySalt,
        },
        [
          {
            tenantId: row.tenantId,
            agentId: row.agentId,
            name: `pending-proxy:${row.requestDigest}`,
          },
        ],
      );
      if (resolved.status === "already") result.alreadyRotated += 1;
      else {
        if (!dryRun) {
          await db
            .update(pendingProxyRequests)
            .set({
              bodyCiphertext: resolved.enc.ciphertext,
              bodyIv: resolved.enc.iv,
              bodyAuthTag: resolved.enc.tag,
              bodySalt: resolved.enc.salt,
            })
            .where(eq(pendingProxyRequests.id, row.id));
        }
        result.rotated += 1;
      }
    } catch {
      result.failed.push(`id=${row.id}: authentication failed`);
    }
  }
  return result;
}

// Per-tenant email API keys are JSON-serialized, contextless legacy KeyStore
// payloads nested in tenant_configs.email_config.
export async function rotateTenantEmailConfigs(
  db: Db,
  roots: RootKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("tenant_email_configs");
  const rows = await db.select().from(tenantConfigs).orderBy(tenantConfigs.tenantId);
  for (const row of rows) {
    const encryptedJson = row.emailConfig?.apiKeyEncrypted;
    if (!encryptedJson) continue;
    if (result.firstId === null) result.firstId = row.tenantId;
    result.lastId = row.tenantId;
    try {
      const encrypted = JSON.parse(encryptedJson) as EncryptedKey;
      const resolved = resolveRow(roots, encrypted, [undefined]);
      if (resolved.status === "already") result.alreadyRotated += 1;
      else {
        if (!dryRun) {
          await db
            .update(tenantConfigs)
            .set({
              emailConfig: { ...row.emailConfig, apiKeyEncrypted: JSON.stringify(resolved.enc) },
            })
            .where(eq(tenantConfigs.tenantId, row.tenantId));
        }
        result.rotated += 1;
      }
    } catch {
      result.failed.push(`tenant_id=${row.tenantId}: authentication failed`);
    }
  }
  return result;
}

const WEBHOOK_PREFIX = "stwd_whsec_v1:";

type WebhookRoots = RotationKeystores["webhook"];

function webhookRoot(password: string, salt: string): Buffer {
  const saltBytes = salt ? Buffer.from(salt, "hex") : Buffer.from("steward-webhook-secret-v1");
  return scryptSync(password, saltBytes, 32) as Buffer;
}

function decryptWebhook(value: string, password: string, configuredSalt: string): string {
  if (!value.startsWith(WEBHOOK_PREFIX)) {
    throw new Error("plaintext webhook secret requires separate migration before root rotation");
  }
  const payload = JSON.parse(value.slice(WEBHOOK_PREFIX.length)) as EncryptedKey;
  const key = scryptSync(
    webhookRoot(password, configuredSalt),
    Buffer.from(payload.salt, "hex"),
    32,
  );
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "hex"));
  decipher.setAuthTag(Buffer.from(payload.tag, "hex"));
  return decipher.update(payload.ciphertext, "hex", "utf8") + decipher.final("utf8");
}

function encryptWebhook(value: string, password: string, configuredSalt: string): string {
  const iv = randomBytes(16);
  const salt = randomBytes(16);
  const key = scryptSync(webhookRoot(password, configuredSalt), salt, 32);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = cipher.update(value, "utf8", "hex") + cipher.final("hex");
  return `${WEBHOOK_PREFIX}${JSON.stringify({
    ciphertext,
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    salt: salt.toString("hex"),
  })}`;
}

export async function rotateWebhookConfigs(
  db: Db,
  roots: WebhookRoots,
  dryRun: boolean,
): Promise<RotateResult> {
  const result = emptyResult("webhook_configs");
  const rows = await db.select().from(webhookConfigs).orderBy(webhookConfigs.id);
  for (const row of rows) {
    if (result.firstId === null) result.firstId = row.id;
    result.lastId = row.id;
    try {
      try {
        decryptWebhook(row.secret, roots.newPassword, roots.newSalt);
        result.alreadyRotated += 1;
        continue;
      } catch {
        // Expected before cutover. Authenticate with the old root next.
      }
      const plaintext = decryptWebhook(row.secret, roots.oldPassword, roots.oldSalt);
      const encrypted = encryptWebhook(plaintext, roots.newPassword, roots.newSalt);
      if (!dryRun) {
        await db
          .update(webhookConfigs)
          .set({ secret: encrypted })
          .where(eq(webhookConfigs.id, row.id));
      }
      result.rotated += 1;
    } catch {
      result.failed.push(`id=${row.id}: authentication failed`);
    }
  }
  return result;
}

// ─────────────────────────────── shared helpers ──────────────────────────────

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : "non-Error thrown";
}

// ───────────────────────────── root construction ─────────────────────────────

/**
 * Build the keystore roots for a logical encryption domain.
 *
 * @param oldPw/oldSalt  OLD password + salt
 * @param newPw/newSalt  NEW password + salt
 * @param domain         KDF domain label (undefined = legacy/undomained root)
 */
export function buildRoots(
  oldPw: string,
  oldSalt: string | undefined,
  newPw: string,
  newSalt: string,
  domain?: KeyStoreDomain,
): RootKeystores {
  return {
    old: new KeyStore(oldPw, oldSalt, domain),
    new: new KeyStore(newPw, newSalt, domain),
  };
}

export interface RotationKeystores {
  /** Wallet signing-vault root (no KDF domain, matches Vault). */
  signing: RootKeystores;
  /** Secret-vault domain root (matches SecretVault primary). */
  secretDomain: RootKeystores;
  /** Legacy undomained root (OAuth tokens + pre-separation secrets). */
  legacy: RootKeystores;
  webhook: { oldPassword: string; oldSalt: string; newPassword: string; newSalt: string };
}

export function buildRotationKeystores(
  oldPw: string,
  oldSalt: string | undefined,
  newPw: string,
  newSalt: string,
): RotationKeystores {
  const runtimeEnv: Record<string, string | undefined> = process.env;
  return {
    // Vault encrypts wallet keys with `new KeyStore(masterPassword, salt)`, no
    // domain label. (vault.ts constructor.)
    signing: buildRoots(oldPw, oldSalt, newPw, newSalt),
    // SecretVault primary root is domain "secret-vault". (secret-vault.ts:205.)
    secretDomain: buildRoots(oldPw, oldSalt, newPw, newSalt, "secret-vault"),
    // SecretVault legacy fallback + OAuth tokens use the undomained root.
    legacy: buildRoots(oldPw, oldSalt, newPw, newSalt),
    webhook: {
      oldPassword: runtimeEnv.STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY ?? oldPw,
      oldSalt: runtimeEnv.STEWARD_WEBHOOK_SECRET_KDF_SALT ?? oldSalt ?? "",
      newPassword:
        runtimeEnv.STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY_NEW ??
        runtimeEnv.STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY ??
        newPw,
      newSalt:
        runtimeEnv.STEWARD_WEBHOOK_SECRET_KDF_SALT_NEW ??
        runtimeEnv.STEWARD_WEBHOOK_SECRET_KDF_SALT ??
        newSalt,
    },
  };
}

/**
 * Rotate a single table. Exported so callers (and the test) can drive each
 * table directly with a chosen Db handle. Resolves the correct keystore root(s)
 * per table.
 */
export async function rotateTable(
  table: TableName,
  db: Db,
  ks: RotationKeystores,
  dryRun: boolean,
): Promise<RotateResult> {
  switch (table) {
    case "encrypted_keys":
      return rotateEncryptedKeys(db, ks.signing, dryRun);
    case "encrypted_chain_keys":
      return rotateEncryptedChainKeys(db, ks.signing, dryRun);
    case "secrets":
      return rotateSecrets(db, ks.secretDomain, ks.legacy, dryRun);
    case "accounts":
      return rotateAccounts(db, ks.legacy, dryRun);
    case "tenant_request_signing_keys":
      return rotateTenantRequestSigningKeys(db, ks.secretDomain, dryRun);
    case "pending_proxy_requests":
      return rotatePendingProxyRequests(db, ks.secretDomain, dryRun);
    case "tenant_email_configs":
      return rotateTenantEmailConfigs(db, ks.legacy, dryRun);
    case "webhook_configs":
      return rotateWebhookConfigs(db, ks.webhook, dryRun);
  }
}

function summarize(res: RotateResult, dryRun: boolean): string {
  const span = res.firstId && res.lastId ? ` [${res.firstId} .. ${res.lastId}]` : "";
  const parts = [
    `rotated=${res.rotated}`,
    `already=${res.alreadyRotated}`,
    `failed=${res.failed.length}`,
  ];
  return `[rotate] ${res.table}: ${parts.join(" ")}${span}${dryRun ? " (dry-run)" : ""}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const oldPw = requireEnv("STEWARD_MASTER_PASSWORD");
  const oldSalt = process.env.STEWARD_KDF_SALT;
  const newPw = requireEnv("STEWARD_MASTER_PASSWORD_NEW");
  const newSalt = requireEnv("STEWARD_KDF_SALT_NEW");

  if (newPw === oldPw && newSalt === oldSalt) {
    throw new Error("NEW password+salt are identical to OLD, nothing to rotate");
  }

  validateArgs(args);

  const ks = buildRotationKeystores(oldPw, oldSalt, newPw, newSalt);
  const tables: TableName[] = args.table ? [args.table] : ALL_TABLES;
  const { client, db } = createDb();
  let lockHeld = false;
  const failures: string[] = [];

  try {
    const lockRows = (await db.execute(
      sql`SELECT pg_try_advisory_lock(${LOCK_KEY_SQL}) AS got`,
    )) as unknown as Array<{ got: boolean }>;
    const got = Array.isArray(lockRows) ? lockRows[0]?.got : undefined;
    if (!got) {
      throw new Error("Another rotation run holds the steward_rotation advisory lock");
    }
    lockHeld = true;

    // Complete preflight happens before the first mutation. This prevents a bad
    // old password or one malformed inventory row from creating a mixed-key DB.
    const preflight: RotateResult[] = [];
    for (const table of tables) {
      const res = await rotateTable(table, db, ks, true);
      preflight.push(res);
      console.log(summarize(res, true));
      for (const failure of res.failed) failures.push(`${table}: ${failure}`);
    }
    if (failures.length > 0) {
      throw new Error(
        `preflight failed for ${failures.length} encrypted item(s); no writes performed`,
      );
    }

    if (!args.dryRun) {
      // One DB transaction is the journal. Any write error rolls every class
      // back, so an interrupted invocation can be rerun safely.
      await db.transaction(async (tx) => {
        for (const table of tables) {
          const res = await rotateTable(table, tx as Db, ks, false);
          if (res.failed.length > 0) {
            throw new Error(`${table} changed after preflight; transaction rolled back`);
          }
          console.log(summarize(res, false));
        }
      });

      await writeAuditEvent({
        tenantId: "system",
        actorType: "system",
        action: "system.master_password_rotation.complete",
        resourceType: "encrypted_inventory",
        resourceId: "all",
        metadata: {
          tables,
          preflightCounts: preflight.map((result) => ({
            table: result.table,
            rotated: result.rotated,
            alreadyRotated: result.alreadyRotated,
          })),
        },
      });
    }
  } catch (err) {
    console.error(`ROTATION ABORTED: ${errMsg(err)}`);
    process.exitCode = 1;
  } finally {
    if (lockHeld) {
      await db.execute(sql`SELECT pg_advisory_unlock(${LOCK_KEY_SQL})`).catch(() => {});
    }
    await client.end();
  }

  if (failures.length > 0) {
    console.error(
      `ROTATION COMPLETED WITH ${failures.length} UNDECRYPTABLE ROW(S). ` +
        `These rows were left untouched (no data loss) and must be investigated:`,
    );
    for (const f of failures) console.error(`  - ${f}`);
    process.exitCode = 1;
  }
}

// Only auto-run when invoked directly (not when imported by the test).
if (import.meta.main) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
