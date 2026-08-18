import { createHash, timingSafeEqual } from "node:crypto";
import {
  type AppendRequiredAudit,
  and,
  asc,
  eq,
  gt,
  isNotNull,
  isNull,
  lte,
  or,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
} from "@stwd/db";
import { capabilities, capabilityGrants } from "./schema";

export const GITHUB_APP_LEASE_ISSUER = "github-app-installation";
export const MAX_UPSTREAM_LEASE_TTL_SECONDS = 3600;
export const GITHUB_INSTALLATION_TOKEN_TTL_SECONDS = 3600;
const MIN_GITHUB_ISSUED_TTL_MS = 55 * 60 * 1000;
const MAX_GITHUB_ISSUED_TTL_MS = (GITHUB_INSTALLATION_TOKEN_TTL_SECONDS + 30) * 1000;
const REVOCATION_CLAIM_TIMEOUT_MS = 30_000;
export const DELIVERY_ACK_TIMEOUT_MS = 30_000;
export const MAX_UPSTREAM_LEASE_SWEEP_INTERVAL_MS = DELIVERY_ACK_TIMEOUT_MS / 2;

export interface GitHubLeaseResource {
  repositories: string[];
  permissions: Record<string, "read" | "write" | "admin">;
}

export interface GitHubAppLeaseConfig {
  issuer: typeof GITHUB_APP_LEASE_ISSUER;
  workspaceId: string;
  appId: string;
  installationId: string;
  allowedRepositories: string[];
  allowedPermissions: Record<string, "read" | "write" | "admin">;
  maxTtlSeconds?: number;
}

export interface UpstreamTokenIssuer {
  issue(input: {
    appId: string;
    installationId: string;
    privateKeyPem: string;
    resource: GitHubLeaseResource;
  }): Promise<{ token: string; expiresAt: Date }>;
  revoke(token: string): Promise<void>;
}

export type ExerciseCredentialSecret = <T>(
  tenantId: string,
  secretId: string,
  use: (plaintext: string) => Promise<T>,
) => Promise<T>;
export interface SealedLeaseToken {
  ciphertext: string;
  iv: string;
  tag: string;
  salt: string;
}
export type SealLeaseToken = (
  tenantId: string,
  leaseId: string,
  token: string,
) => Promise<SealedLeaseToken>;
export type ExerciseLeaseToken = <T>(
  tenantId: string,
  leaseId: string,
  sealed: SealedLeaseToken,
  use: (token: string) => Promise<T>,
) => Promise<T>;
export type LeaseAuditedTransaction = <T>(
  tenantId: string,
  fn: (tx: Db, appendRequiredAudit: AppendRequiredAudit) => Promise<T>,
) => Promise<T>;

type Db = any;

let beforeRecoveryClaimForTests: ((leaseId: string) => Promise<void>) | undefined;

/** Deterministic interleaving hook for the recovery CAS tests only. */
export function __setBeforeUpstreamLeaseRecoveryClaimForTests(
  hook?: (leaseId: string) => Promise<void>,
): void {
  beforeRecoveryClaimForTests = hook;
}

async function readLiveLeaseAuthority(
  db: Db,
  input: {
    tenantId: string;
    agentId: string;
    capabilityId: string;
    grantId: string;
  },
  now: Date,
  lock = false,
): Promise<{ secretId: string; config: GitHubAppLeaseConfig; grantExpiresAt: Date | null } | null> {
  let query = db
    .select({
      id: capabilityGrants.id,
      secretId: capabilities.secretId,
      constraints: capabilities.constraints,
      grantExpiresAt: capabilityGrants.expiresAt,
    })
    .from(capabilityGrants)
    .innerJoin(
      capabilities,
      and(
        eq(capabilities.id, capabilityGrants.capabilityId),
        eq(capabilities.tenantId, capabilityGrants.tenantId),
      ),
    )
    .where(
      and(
        eq(capabilityGrants.id, input.grantId),
        eq(capabilityGrants.tenantId, input.tenantId),
        eq(capabilityGrants.agentId, input.agentId),
        eq(capabilityGrants.capabilityId, input.capabilityId),
        eq(capabilityGrants.status, "active"),
        or(isNull(capabilityGrants.expiresAt), gt(capabilityGrants.expiresAt, now)),
        eq(capabilities.id, input.capabilityId),
        eq(capabilities.tenantId, input.tenantId),
        eq(capabilities.enabled, true),
      ),
    )
    .limit(1);
  if (lock) query = query.for("share");
  const [row] = await query;
  if (!row) return null;
  const config = parseGitHubLeaseConfig(row.constraints);
  return config ? { secretId: row.secretId, config, grantExpiresAt: row.grantExpiresAt } : null;
}

function coreAuditEvent(input: {
  tenantId: string;
  leaseId: string;
  action: string;
  actorType?: "agent" | "system" | "user";
  actorId?: string;
  metadata?: Record<string, unknown>;
}) {
  return {
    tenantId: input.tenantId,
    actorType: input.actorType ?? ("system" as const),
    ...(input.actorId ? { actorId: input.actorId } : {}),
    action: input.action,
    resourceType: "upstream-credential-lease",
    resourceId: input.leaseId,
    metadata: input.metadata ?? {},
  };
}

function leaseAuthorityDigest(secretId: string, config: GitHubAppLeaseConfig): string {
  return sha256(
    JSON.stringify({
      secretId,
      issuer: config.issuer,
      workspaceId: config.workspaceId,
      appId: config.appId,
      installationId: config.installationId,
      allowedRepositories: [...new Set(config.allowedRepositories)].sort(),
      allowedPermissions: Object.fromEntries(
        Object.entries(config.allowedPermissions).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
      ),
      maxTtlSeconds: config.maxTtlSeconds ?? MAX_UPSTREAM_LEASE_TTL_SECONDS,
    }),
  );
}

export type LeaseIssueResult =
  | {
      ok: true;
      leaseId: string;
      token: string;
      expiresAt: string;
      resource: GitHubLeaseResource;
    }
  | {
      ok: false;
      status: 400 | 403 | 409 | 503;
      code: string;
      error: string;
    };

const permissionRank = { read: 1, write: 2, admin: 3 } as const;

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalGitHubLeaseResource(resource: GitHubLeaseResource): GitHubLeaseResource {
  const repositories = [...new Set(resource.repositories.map((value) => value.trim()))].sort();
  const permissions = Object.fromEntries(
    Object.entries(resource.permissions)
      .map(([key, value]) => [key.trim(), value] as const)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  return { repositories, permissions };
}

function resourceHash(resource: GitHubLeaseResource): string {
  return sha256(JSON.stringify(canonicalGitHubLeaseResource(resource)));
}

export function parseGitHubLeaseConfig(constraints: unknown): GitHubAppLeaseConfig | null {
  if (!constraints || typeof constraints !== "object" || Array.isArray(constraints)) return null;
  const raw = (constraints as Record<string, unknown>).upstreamLease;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const value = raw as Record<string, unknown>;
  if (
    value.issuer !== GITHUB_APP_LEASE_ISSUER ||
    typeof value.workspaceId !== "string" ||
    typeof value.appId !== "string" ||
    typeof value.installationId !== "string" ||
    !Array.isArray(value.allowedRepositories) ||
    !value.allowedRepositories.every((entry) => typeof entry === "string") ||
    !value.allowedPermissions ||
    typeof value.allowedPermissions !== "object" ||
    Array.isArray(value.allowedPermissions)
  ) {
    return null;
  }
  const permissions = value.allowedPermissions as Record<string, unknown>;
  if (
    !Object.values(permissions).every(
      (entry) => entry === "read" || entry === "write" || entry === "admin",
    )
  ) {
    return null;
  }
  const maxTtlSeconds = value.maxTtlSeconds;
  if (maxTtlSeconds !== undefined && maxTtlSeconds !== GITHUB_INSTALLATION_TOKEN_TTL_SECONDS) {
    return null;
  }
  return {
    issuer: GITHUB_APP_LEASE_ISSUER,
    workspaceId: value.workspaceId,
    appId: value.appId,
    installationId: value.installationId,
    allowedRepositories: value.allowedRepositories as string[],
    allowedPermissions: permissions as GitHubAppLeaseConfig["allowedPermissions"],
    ...(maxTtlSeconds === undefined ? {} : { maxTtlSeconds: maxTtlSeconds as number }),
  };
}

function validateResource(
  requested: GitHubLeaseResource,
  config: GitHubAppLeaseConfig,
): GitHubLeaseResource | null {
  const normalized = canonicalGitHubLeaseResource(requested);
  if (
    normalized.repositories.length === 0 ||
    normalized.repositories.length > 500 ||
    normalized.repositories.some(
      (repository) =>
        !/^[A-Za-z0-9_.-]{1,100}$/.test(repository) ||
        !config.allowedRepositories.includes(repository),
    )
  ) {
    return null;
  }
  const entries = Object.entries(normalized.permissions);
  if (entries.length === 0) return null;
  for (const [permission, level] of entries) {
    const allowed = config.allowedPermissions[permission];
    if (!allowed || permissionRank[level] > permissionRank[allowed]) return null;
  }
  return normalized;
}

async function recordFailure(
  auditedTransaction: LeaseAuditedTransaction,
  leaseId: string,
  tenantId: string,
  error: string,
  status: "failed" | "needs_attention" = "failed",
): Promise<void> {
  await auditedTransaction(tenantId, async (tx: Db, appendRequiredAudit) => {
    const updated = await tx
      .update(upstreamCredentialLeases)
      .set({ status, lastError: error.slice(0, 500), updatedAt: new Date() })
      .where(
        and(
          eq(upstreamCredentialLeases.id, leaseId),
          eq(upstreamCredentialLeases.tenantId, tenantId),
          or(
            eq(upstreamCredentialLeases.status, "issuing"),
            eq(upstreamCredentialLeases.status, "delivery_pending"),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        ),
      )
      .returning({ id: upstreamCredentialLeases.id });
    if (updated.length === 0) return;
    await tx.insert(upstreamCredentialLeaseEvents).values({
      leaseId,
      tenantId,
      action: "lease.issue",
      decision: "deny",
      metadata: { reason: error.slice(0, 200) },
    });
    await appendRequiredAudit(
      coreAuditEvent({
        tenantId,
        leaseId,
        action: `upstream_credential_lease.${status}`,
        metadata: { reason: error.slice(0, 200) },
      }),
    );
  });
}

async function recordRecoverableSealedFailure(input: {
  db: Db;
  auditedTransaction: LeaseAuditedTransaction;
  leaseId: string;
  tenantId: string;
  token: string;
  sealed: SealedLeaseToken;
  expiresAt: Date | null;
  error: string;
  now: Date;
}): Promise<void> {
  await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
    const persisted = await tx
      .update(upstreamCredentialLeases)
      .set({
        tokenHash: sha256(input.token),
        tokenCiphertext: input.sealed.ciphertext,
        tokenIv: input.sealed.iv,
        tokenAuthTag: input.sealed.tag,
        tokenSalt: input.sealed.salt,
        expiresAt: input.expiresAt,
        status: "needs_attention",
        lastError: input.error.slice(0, 500),
        updatedAt: input.now,
      })
      .where(
        and(
          eq(upstreamCredentialLeases.id, input.leaseId),
          eq(upstreamCredentialLeases.tenantId, input.tenantId),
          or(
            eq(upstreamCredentialLeases.status, "issuing"),
            eq(upstreamCredentialLeases.status, "delivery_pending"),
            eq(upstreamCredentialLeases.status, "needs_attention"),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        ),
      )
      .returning({ id: upstreamCredentialLeases.id });
    if (persisted.length !== 1) throw new Error("lease recovery handle could not be persisted");
    await tx.insert(upstreamCredentialLeaseEvents).values({
      leaseId: input.leaseId,
      tenantId: input.tenantId,
      action: "lease.issue",
      decision: "deny",
      metadata: { reason: input.error.slice(0, 200), recoverableRevocationHandle: true },
    });
    await appendRequiredAudit(
      coreAuditEvent({
        tenantId: input.tenantId,
        leaseId: input.leaseId,
        action: "upstream_credential_lease.needs_attention",
        metadata: { reason: input.error.slice(0, 200), recoverableRevocationHandle: true },
      }),
    );
  });
}

async function persistPendingSealedRevocation(input: {
  db: Db;
  leaseId: string;
  tenantId: string;
  token: string;
  sealed: SealedLeaseToken;
  expiresAt: Date | null;
  error: string;
  now: Date;
}): Promise<void> {
  const persisted = await input.db
    .update(upstreamCredentialLeases)
    .set({
      tokenHash: sha256(input.token),
      tokenCiphertext: input.sealed.ciphertext,
      tokenIv: input.sealed.iv,
      tokenAuthTag: input.sealed.tag,
      tokenSalt: input.sealed.salt,
      expiresAt: input.expiresAt,
      status: "revoking",
      lastError: input.error.slice(0, 500),
      updatedAt: input.now,
    })
    .where(
      and(
        eq(upstreamCredentialLeases.id, input.leaseId),
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        or(
          eq(upstreamCredentialLeases.status, "issuing"),
          eq(upstreamCredentialLeases.status, "delivery_pending"),
        ),
      ),
    )
    .returning({ id: upstreamCredentialLeases.id });
  if (persisted.length !== 1) throw new Error("pending lease revocation could not be persisted");
}

/** Bounded durable expiry sweep. Issuance invokes it opportunistically; a host
 * may also schedule it directly when no new leases are being requested. */
export async function expireUpstreamCredentialLeases(input: {
  db: Db;
  auditedTransaction: LeaseAuditedTransaction;
  tenantId: string;
  now?: Date;
  limit?: number;
}): Promise<number> {
  const now = input.now ?? new Date();
  const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
  return input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
    const due = await tx
      .select({ id: upstreamCredentialLeases.id })
      .from(upstreamCredentialLeases)
      .where(
        and(
          eq(upstreamCredentialLeases.tenantId, input.tenantId),
          eq(upstreamCredentialLeases.status, "active"),
          lte(upstreamCredentialLeases.expiresAt, now),
        ),
      )
      .orderBy(asc(upstreamCredentialLeases.expiresAt), asc(upstreamCredentialLeases.id))
      .limit(limit);
    let expired = 0;
    for (const row of due) {
      const updated = await tx
        .update(upstreamCredentialLeases)
        .set({ status: "expired", updatedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, row.id),
            eq(upstreamCredentialLeases.status, "active"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (updated.length === 0) continue;
      expired += 1;
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: row.id,
        tenantId: input.tenantId,
        action: "lease.expire",
        decision: "allow",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: row.id,
          action: "upstream_credential_lease.expired",
        }),
      );
    }
    return expired;
  });
}

/** Recover issuance/delivery crashes. An `issuing` row has an unknowable
 * provider outcome and is escalated truthfully. A delivery that was never ACKed
 * retains an encrypted revocation handle and is revoked after the bounded ACK
 * window. */
export async function recoverInterruptedUpstreamCredentialLeases(input: {
  db: Db;
  tenantId: string;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  now?: Date;
  limit?: number;
}): Promise<{ unknown: number; revoked: number; attention: number }> {
  const now = input.now ?? new Date();
  const cutoff = new Date(now.getTime() - DELIVERY_ACK_TIMEOUT_MS);
  const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const active = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      and(
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        eq(upstreamCredentialLeases.status, "active"),
      ),
    )
    .orderBy(asc(upstreamCredentialLeases.authorityCheckedAt), asc(upstreamCredentialLeases.id))
    .limit(limit);
  let revoked = 0;
  let attention = 0;
  for (const lease of active) {
    const live = await readLiveLeaseAuthority(
      input.db,
      {
        tenantId: input.tenantId,
        agentId: lease.agentId,
        capabilityId: lease.capabilityId,
        grantId: lease.grantId,
      },
      now,
    );
    const authorityValid =
      live !== null &&
      live.config.workspaceId === lease.workspaceId &&
      leaseAuthorityDigest(live.secretId, live.config) === lease.authorityDigest;
    if (authorityValid) {
      await input.db
        .update(upstreamCredentialLeases)
        .set({ authorityCheckedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, "active"),
            eq(upstreamCredentialLeases.authorityCheckedAt, lease.authorityCheckedAt),
          ),
        );
      continue;
    }
    const result = await revokeExactSealedLease({
      db: input.db,
      tenantId: input.tenantId,
      lease,
      issuer: input.issuer,
      exerciseToken: input.exerciseToken,
      auditedTransaction: input.auditedTransaction,
      now,
      mode: "authority_teardown",
    });
    if (result.ok) revoked += result.revoked;
    else attention += 1;
  }
  const stale = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      and(
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        or(
          and(
            eq(upstreamCredentialLeases.status, "issuing"),
            lte(upstreamCredentialLeases.updatedAt, cutoff),
          ),
          and(
            eq(upstreamCredentialLeases.status, "delivery_pending"),
            lte(upstreamCredentialLeases.updatedAt, cutoff),
          ),
          and(
            eq(upstreamCredentialLeases.status, "acknowledging"),
            lte(upstreamCredentialLeases.updatedAt, cutoff),
          ),
          and(
            eq(upstreamCredentialLeases.status, "needs_attention"),
            isNotNull(upstreamCredentialLeases.tokenCiphertext),
            lte(upstreamCredentialLeases.updatedAt, cutoff),
          ),
          and(
            eq(upstreamCredentialLeases.status, "revoking"),
            isNotNull(upstreamCredentialLeases.tokenCiphertext),
            lte(upstreamCredentialLeases.updatedAt, cutoff),
          ),
        ),
      ),
    )
    .orderBy(asc(upstreamCredentialLeases.updatedAt), asc(upstreamCredentialLeases.id))
    .limit(limit);
  let unknown = 0;
  for (const lease of stale) {
    if (lease.status === "issuing") {
      const changed = await input.auditedTransaction(
        input.tenantId,
        async (tx: Db, appendRequiredAudit) => {
          const updated = await tx
            .update(upstreamCredentialLeases)
            .set({
              status: "needs_attention",
              lastError: "issuer outcome unknown after interrupted issuance",
              updatedAt: now,
            })
            .where(
              and(
                eq(upstreamCredentialLeases.id, lease.id),
                eq(upstreamCredentialLeases.status, "issuing"),
                eq(upstreamCredentialLeases.updatedAt, lease.updatedAt),
                lte(upstreamCredentialLeases.updatedAt, cutoff),
              ),
            )
            .returning({ id: upstreamCredentialLeases.id });
          if (updated.length === 0) return updated;
          await tx.insert(upstreamCredentialLeaseEvents).values({
            leaseId: lease.id,
            tenantId: input.tenantId,
            action: "lease.issuer_outcome_unknown",
            decision: "deny",
          });
          await appendRequiredAudit(
            coreAuditEvent({
              tenantId: input.tenantId,
              leaseId: lease.id,
              action: "upstream_credential_lease.issuer_outcome_unknown",
              metadata: { grantId: lease.grantId, capabilityId: lease.capabilityId },
            }),
          );
          return updated;
        },
      );
      if (changed.length === 0) continue;
      unknown += 1;
      continue;
    }
    await beforeRecoveryClaimForTests?.(lease.id);
    const result = await revokeExactSealedLease({
      db: input.db,
      tenantId: input.tenantId,
      lease,
      issuer: input.issuer,
      exerciseToken: input.exerciseToken,
      auditedTransaction: input.auditedTransaction,
      now,
      mode: "stale_recovery",
      staleCutoff: cutoff,
    });
    if (result.ok) revoked += result.revoked;
    else attention += 1;
  }
  return { unknown, revoked, attention };
}

type RecoveryTotals = { unknown: number; revoked: number; attention: number; expired?: number };
type LeaseRow = typeof upstreamCredentialLeases.$inferSelect;

async function recoverOneDueLease(input: {
  db: Db;
  lease: LeaseRow;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  now: Date;
  cutoff: Date;
}): Promise<RecoveryTotals> {
  const { lease } = input;
  if (lease.status === "issuing") {
    const changed = await input.auditedTransaction(
      lease.tenantId,
      async (tx: Db, appendRequiredAudit) => {
        const updated = await tx
          .update(upstreamCredentialLeases)
          .set({
            status: "needs_attention",
            lastError: "issuer outcome unknown after interrupted issuance",
            updatedAt: input.now,
          })
          .where(
            and(
              eq(upstreamCredentialLeases.id, lease.id),
              eq(upstreamCredentialLeases.tenantId, lease.tenantId),
              eq(upstreamCredentialLeases.status, "issuing"),
              eq(upstreamCredentialLeases.updatedAt, lease.updatedAt),
              lte(upstreamCredentialLeases.updatedAt, input.cutoff),
            ),
          )
          .returning({ id: upstreamCredentialLeases.id });
        if (updated.length === 0) return false;
        await tx.insert(upstreamCredentialLeaseEvents).values({
          leaseId: lease.id,
          tenantId: lease.tenantId,
          action: "lease.issuer_outcome_unknown",
          decision: "deny",
        });
        await appendRequiredAudit(
          coreAuditEvent({
            tenantId: lease.tenantId,
            leaseId: lease.id,
            action: "upstream_credential_lease.issuer_outcome_unknown",
            metadata: { grantId: lease.grantId, capabilityId: lease.capabilityId },
          }),
        );
        return true;
      },
    );
    return { unknown: changed ? 1 : 0, revoked: 0, attention: 0 };
  }
  await beforeRecoveryClaimForTests?.(lease.id);
  const result = await revokeExactSealedLease({
    db: input.db,
    tenantId: lease.tenantId,
    lease,
    issuer: input.issuer,
    exerciseToken: input.exerciseToken,
    auditedTransaction: input.auditedTransaction,
    now: input.now,
    mode: "stale_recovery",
    staleCutoff: input.cutoff,
  });
  return result.ok
    ? { unknown: 0, revoked: result.revoked, attention: 0 }
    : { unknown: 0, revoked: 0, attention: 1 };
}

async function recoverOneActiveLease(input: {
  db: Db;
  lease: LeaseRow;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  now: Date;
}): Promise<RecoveryTotals> {
  const { lease } = input;
  const live = await readLiveLeaseAuthority(
    input.db,
    {
      tenantId: lease.tenantId,
      agentId: lease.agentId,
      capabilityId: lease.capabilityId,
      grantId: lease.grantId,
    },
    input.now,
  );
  const authorityValid =
    live !== null &&
    live.config.workspaceId === lease.workspaceId &&
    leaseAuthorityDigest(live.secretId, live.config) === lease.authorityDigest;
  if (authorityValid) {
    await input.db
      .update(upstreamCredentialLeases)
      .set({ authorityCheckedAt: input.now })
      .where(
        and(
          eq(upstreamCredentialLeases.id, lease.id),
          eq(upstreamCredentialLeases.tenantId, lease.tenantId),
          eq(upstreamCredentialLeases.status, "active"),
          eq(upstreamCredentialLeases.authorityCheckedAt, lease.authorityCheckedAt),
        ),
      );
    return { unknown: 0, revoked: 0, attention: 0 };
  }
  const result = await revokeExactSealedLease({
    db: input.db,
    tenantId: lease.tenantId,
    lease,
    issuer: input.issuer,
    exerciseToken: input.exerciseToken,
    auditedTransaction: input.auditedTransaction,
    now: input.now,
    mode: "authority_teardown",
  });
  return result.ok
    ? { unknown: 0, revoked: result.revoked, attention: 0 }
    : { unknown: 0, revoked: 0, attention: 1 };
}

async function expireOneActiveLease(input: {
  lease: LeaseRow;
  auditedTransaction: LeaseAuditedTransaction;
  now: Date;
}): Promise<number> {
  return input.auditedTransaction(input.lease.tenantId, async (tx: Db, appendRequiredAudit) => {
    const updated = await tx
      .update(upstreamCredentialLeases)
      .set({ status: "expired", updatedAt: input.now })
      .where(
        and(
          eq(upstreamCredentialLeases.id, input.lease.id),
          eq(upstreamCredentialLeases.tenantId, input.lease.tenantId),
          eq(upstreamCredentialLeases.status, "active"),
          lte(upstreamCredentialLeases.expiresAt, input.now),
        ),
      )
      .returning({ id: upstreamCredentialLeases.id });
    if (updated.length === 0) return 0;
    await tx.insert(upstreamCredentialLeaseEvents).values({
      leaseId: input.lease.id,
      tenantId: input.lease.tenantId,
      action: "lease.expire",
      decision: "allow",
    });
    await appendRequiredAudit(
      coreAuditEvent({
        tenantId: input.lease.tenantId,
        leaseId: input.lease.id,
        action: "upstream_credential_lease.expired",
      }),
    );
    return 1;
  });
}

async function mapWithDeadline<T>(input: {
  items: T[];
  concurrency: number;
  deadlineAt: number;
  run: (item: T) => Promise<void>;
}): Promise<number> {
  let cursor = 0;
  let started = 0;
  const worker = async () => {
    while (Date.now() < input.deadlineAt) {
      const index = cursor++;
      const item = input.items[index];
      if (item === undefined) return;
      started += 1;
      await input.run(item);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(input.concurrency, input.items.length) }, () => worker()),
  );
  return started;
}

/** Process-bounded autonomous sweep entrypoint. Deadline-due leases are read
 * globally from durable state and handled by a bounded worker pool, so neither
 * tenant-id pagination nor one slow provider call can starve another tenant. */
export async function recoverAllInterruptedUpstreamCredentialLeases(input: {
  db: Db;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  now?: Date;
  /** Global work cap. Ordering is by the oldest recovery deadline, never tenant id. */
  workLimit?: number;
  /** Provider calls are isolated behind a bounded pool so one tenant cannot block another. */
  concurrency?: number;
  /** Stop claiming new work after this wall-clock budget; already claimed work is awaited. */
  runDeadlineMs?: number;
}): Promise<{
  tenants: number;
  unknown: number;
  revoked: number;
  attention: number;
  expired: number;
  remaining: boolean;
}> {
  const now = input.now ?? new Date();
  const cutoff = new Date(now.getTime() - DELIVERY_ACK_TIMEOUT_MS);
  const workLimit = Math.max(1, Math.min(input.workLimit ?? 500, 2_000));
  const concurrency = Math.max(1, Math.min(input.concurrency ?? 16, 64));
  const runDeadlineMs = Math.max(100, Math.min(input.runDeadlineMs ?? 5_000, 10_000));
  const deadlineAt = Date.now() + runDeadlineMs;
  const due: LeaseRow[] = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      or(
        and(
          eq(upstreamCredentialLeases.status, "issuing"),
          lte(upstreamCredentialLeases.updatedAt, cutoff),
        ),
        and(
          eq(upstreamCredentialLeases.status, "delivery_pending"),
          lte(upstreamCredentialLeases.updatedAt, cutoff),
        ),
        and(
          eq(upstreamCredentialLeases.status, "acknowledging"),
          lte(upstreamCredentialLeases.updatedAt, cutoff),
        ),
        and(
          eq(upstreamCredentialLeases.status, "needs_attention"),
          isNotNull(upstreamCredentialLeases.tokenCiphertext),
          lte(upstreamCredentialLeases.updatedAt, cutoff),
        ),
        and(
          eq(upstreamCredentialLeases.status, "revoking"),
          isNotNull(upstreamCredentialLeases.tokenCiphertext),
          lte(upstreamCredentialLeases.updatedAt, cutoff),
        ),
      ),
    )
    .orderBy(asc(upstreamCredentialLeases.updatedAt), asc(upstreamCredentialLeases.id))
    .limit(workLimit + 1);
  const candidates = due.slice(0, workLimit);
  const touchedTenants = new Set<string>();
  const totals = {
    tenants: 0,
    unknown: 0,
    revoked: 0,
    attention: 0,
    expired: 0,
    remaining: due.length > workLimit,
  };
  const started = await mapWithDeadline({
    items: candidates,
    concurrency,
    deadlineAt,
    run: async (lease) => {
      touchedTenants.add(lease.tenantId);
      try {
        const recovered = await recoverOneDueLease({ ...input, lease, now, cutoff });
        totals.unknown += recovered.unknown;
        totals.revoked += recovered.revoked;
        totals.attention += recovered.attention;
      } catch {
        // A failed tenant transaction or provider must not starve other due leases.
        totals.attention += 1;
      }
    },
  });
  let remainingCapacity = workLimit - started;
  if (remainingCapacity > 0 && Date.now() < deadlineAt) {
    const expired: LeaseRow[] = await input.db
      .select()
      .from(upstreamCredentialLeases)
      .where(
        and(
          eq(upstreamCredentialLeases.status, "active"),
          lte(upstreamCredentialLeases.expiresAt, now),
        ),
      )
      .orderBy(asc(upstreamCredentialLeases.expiresAt), asc(upstreamCredentialLeases.id))
      .limit(remainingCapacity + 1);
    const expiredCandidates = expired.slice(0, remainingCapacity);
    const expiredStarted = await mapWithDeadline({
      items: expiredCandidates,
      concurrency,
      deadlineAt,
      run: async (lease) => {
        touchedTenants.add(lease.tenantId);
        try {
          totals.expired += await expireOneActiveLease({
            lease,
            auditedTransaction: input.auditedTransaction,
            now,
          });
        } catch {
          totals.attention += 1;
        }
      },
    });
    remainingCapacity -= expiredStarted;
    totals.remaining ||=
      expired.length > expiredCandidates.length || expiredStarted < expiredCandidates.length;
  }
  if (remainingCapacity > 0 && Date.now() < deadlineAt) {
    const active: LeaseRow[] = await input.db
      .select()
      .from(upstreamCredentialLeases)
      .where(
        and(
          eq(upstreamCredentialLeases.status, "active"),
          gt(upstreamCredentialLeases.expiresAt, now),
        ),
      )
      .orderBy(
        asc(upstreamCredentialLeases.authorityCheckedAt),
        asc(upstreamCredentialLeases.expiresAt),
        asc(upstreamCredentialLeases.id),
      )
      .limit(remainingCapacity + 1);
    const activeCandidates = active.slice(0, remainingCapacity);
    const activeStarted = await mapWithDeadline({
      items: activeCandidates,
      concurrency,
      deadlineAt,
      run: async (lease) => {
        touchedTenants.add(lease.tenantId);
        try {
          const recovered = await recoverOneActiveLease({ ...input, lease, now });
          totals.unknown += recovered.unknown;
          totals.revoked += recovered.revoked;
          totals.attention += recovered.attention;
          totals.expired += recovered.expired ?? 0;
        } catch {
          totals.attention += 1;
        }
      },
    });
    totals.remaining ||=
      active.length > remainingCapacity || activeStarted < activeCandidates.length;
  }
  totals.tenants = touchedTenants.size;
  totals.remaining ||= started < candidates.length;
  return totals;
}

export async function issueUpstreamCredentialLease(input: {
  db: Db;
  tenantId: string;
  agentId: string;
  workspaceId: string;
  idempotencyKey: string;
  ttlSeconds: number;
  resource: GitHubLeaseResource;
  resolved: {
    capability: { id: string; tenantId: string; secretId: string; constraints: unknown };
    grant: { id: string; tenantId: string; agentId: string; capabilityId: string };
  };
  exerciseSecret: ExerciseCredentialSecret;
  sealToken: SealLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  issuer: UpstreamTokenIssuer;
  now?: Date;
}): Promise<LeaseIssueResult> {
  try {
    await expireUpstreamCredentialLeases({
      db: input.db,
      auditedTransaction: input.auditedTransaction,
      tenantId: input.tenantId,
      now: input.now,
    });
  } catch {
    return {
      ok: false,
      status: 503,
      code: "lease_store_unavailable",
      error: "credential lease store unavailable",
    };
  }
  const config = parseGitHubLeaseConfig(input.resolved.capability.constraints);
  if (
    input.resolved.capability.tenantId !== input.tenantId ||
    input.resolved.grant.tenantId !== input.tenantId ||
    input.resolved.grant.agentId !== input.agentId ||
    input.resolved.grant.capabilityId !== input.resolved.capability.id
  ) {
    return {
      ok: false,
      status: 403,
      code: "binding_denied",
      error: "grant binding does not match the authenticated principal",
    };
  }
  if (!config || config.workspaceId !== input.workspaceId) {
    return {
      ok: false,
      status: 403,
      code: "lease_not_configured",
      error: "upstream lease is not configured for this workspace",
    };
  }
  if (input.ttlSeconds !== GITHUB_INSTALLATION_TOKEN_TTL_SECONDS) {
    return {
      ok: false,
      status: 400,
      code: "ttl_out_of_range",
      error: `GitHub App installation-token ttlSeconds must be ${GITHUB_INSTALLATION_TOKEN_TTL_SECONDS}`,
    };
  }
  if (input.idempotencyKey.length < 16 || input.idempotencyKey.length > 255) {
    return {
      ok: false,
      status: 400,
      code: "invalid_idempotency_key",
      error: "Idempotency-Key must be 16-255 characters",
    };
  }
  const resource = validateResource(input.resource, config);
  if (!resource) {
    return {
      ok: false,
      status: 403,
      code: "scope_denied",
      error: "requested upstream scope is not allowed",
    };
  }
  const now = input.now ?? new Date();
  const expectedAuthorityDigest = config
    ? leaseAuthorityDigest(input.resolved.capability.secretId, config)
    : "";
  const claimResult = await input.db.transaction(async (tx: Db) => {
    const live = await readLiveLeaseAuthority(
      tx,
      {
        tenantId: input.tenantId,
        agentId: input.agentId,
        capabilityId: input.resolved.capability.id,
        grantId: input.resolved.grant.id,
      },
      now,
      true,
    );
    if (!live || leaseAuthorityDigest(live.secretId, live.config) !== expectedAuthorityDigest) {
      return { kind: "authority_denied" as const };
    }
    const [claim] = await tx
      .insert(upstreamCredentialLeases)
      .values({
        tenantId: input.tenantId,
        workspaceId: input.workspaceId,
        agentId: input.agentId,
        grantId: input.resolved.grant.id,
        capabilityId: input.resolved.capability.id,
        issuer: config.issuer,
        resource,
        resourceHash: resourceHash(resource),
        authorityDigest: expectedAuthorityDigest,
        idempotencyKeyHash: sha256(input.idempotencyKey),
        status: "issuing",
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoNothing()
      .returning({ id: upstreamCredentialLeases.id });
    return claim ? { kind: "claimed" as const, claim } : { kind: "replay" as const };
  });
  if (claimResult.kind === "authority_denied") {
    return {
      ok: false,
      status: 403,
      code: "binding_denied",
      error: "grant or capability is no longer active",
    };
  }
  if (claimResult.kind === "replay") {
    return {
      ok: false,
      status: 409,
      code: "lease_replay",
      error: "this issuance key was already consumed; credentials are never replayed",
    };
  }
  const { claim } = claimResult;

  let issued: { token: string; expiresAt: Date };
  try {
    issued = await input.exerciseSecret(
      input.tenantId,
      input.resolved.capability.secretId,
      async (privateKeyPem) =>
        input.issuer.issue({
          appId: config.appId,
          installationId: config.installationId,
          privateKeyPem,
          resource,
        }),
    );
  } catch {
    await recordFailure(
      input.auditedTransaction,
      claim.id,
      input.tenantId,
      "upstream issuer outcome is unknown",
      "needs_attention",
    );
    return {
      ok: false,
      status: 503,
      code: "issuer_unavailable",
      error: "upstream credential issuer unavailable",
    };
  }

  let sealed: SealedLeaseToken;
  try {
    sealed = await input.sealToken(input.tenantId, claim.id, issued.token);
  } catch {
    const revoked = await input.issuer.revoke(issued.token).then(
      () => true,
      () => false,
    );
    await recordFailure(
      input.auditedTransaction,
      claim.id,
      input.tenantId,
      "credential escrow failed",
      revoked ? "failed" : "needs_attention",
    );
    return {
      ok: false,
      status: 503,
      code: "lease_finalization_failed",
      error: "credential delivery was aborted",
    };
  }

  // GitHub chooses a one-hour installation-token expiry and does not accept a
  // requested TTL. Validate the official response shape without pretending a
  // shorter local lifetime can constrain a credential that remains live there.
  const issuedLifetimeMs = issued.expiresAt.getTime() - now.getTime();
  if (
    !issued.token ||
    !Number.isFinite(issued.expiresAt.getTime()) ||
    issuedLifetimeMs < MIN_GITHUB_ISSUED_TTL_MS ||
    issuedLifetimeMs > MAX_GITHUB_ISSUED_TTL_MS
  ) {
    const durableExpiry = Number.isFinite(issued.expiresAt.getTime()) ? issued.expiresAt : null;
    try {
      await persistPendingSealedRevocation({
        db: input.db,
        leaseId: claim.id,
        tenantId: input.tenantId,
        token: issued.token,
        sealed,
        expiresAt: durableExpiry,
        error: "invalid upstream token awaiting revocation confirmation",
        now,
      });
    } catch {
      // A storage outage must not prevent the only in-frame cleanup attempt.
      // If provider revocation is also ambiguous, make one final durable escrow
      // attempt and otherwise propagate rather than pretending cleanup worked.
      const revoked = await input.issuer.revoke(issued.token).then(
        () => true,
        () => false,
      );
      if (revoked) {
        await recordFailure(
          input.auditedTransaction,
          claim.id,
          input.tenantId,
          "invalid upstream token revoked but escrow staging failed",
          "failed",
        );
      } else {
        await recordRecoverableSealedFailure({
          db: input.db,
          auditedTransaction: input.auditedTransaction,
          leaseId: claim.id,
          tenantId: input.tenantId,
          token: issued.token,
          sealed,
          expiresAt: durableExpiry,
          error: "invalid upstream token; escrow and revocation outcomes unknown",
          now,
        });
      }
      return {
        ok: false,
        status: 503,
        code: "issuer_contract_violation",
        error: "upstream issuer returned an invalid expiry",
      };
    }
    const revoked = await input.issuer.revoke(issued.token).then(
      () => true,
      () => false,
    );
    if (revoked) {
      await recordFailure(
        input.auditedTransaction,
        claim.id,
        input.tenantId,
        "upstream expiry did not match GitHub's one-hour installation-token contract",
        "failed",
      );
    } else {
      await recordRecoverableSealedFailure({
        db: input.db,
        auditedTransaction: input.auditedTransaction,
        leaseId: claim.id,
        tenantId: input.tenantId,
        token: issued.token,
        sealed,
        expiresAt: durableExpiry,
        error: "invalid upstream token; revocation outcome unknown",
        now,
      });
    }
    return {
      ok: false,
      status: 503,
      code: "issuer_contract_violation",
      error: "upstream issuer returned an invalid expiry",
    };
  }

  let authorityInvalidated = false;
  try {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const live = await readLiveLeaseAuthority(
        tx,
        {
          tenantId: input.tenantId,
          agentId: input.agentId,
          capabilityId: input.resolved.capability.id,
          grantId: input.resolved.grant.id,
        },
        input.now ?? new Date(),
        true,
      );
      if (!live || leaseAuthorityDigest(live.secretId, live.config) !== expectedAuthorityDigest) {
        authorityInvalidated = true;
        return;
      }
      if (live.grantExpiresAt && live.grantExpiresAt.getTime() < issued.expiresAt.getTime()) {
        authorityInvalidated = true;
        return;
      }
      const finalized = await tx
        .update(upstreamCredentialLeases)
        .set({
          tokenHash: sha256(issued.token),
          tokenCiphertext: sealed.ciphertext,
          tokenIv: sealed.iv,
          tokenAuthTag: sealed.tag,
          tokenSalt: sealed.salt,
          status: "delivery_pending",
          expiresAt: issued.expiresAt,
          updatedAt: now,
        })
        .where(
          and(
            eq(upstreamCredentialLeases.id, claim.id),
            eq(upstreamCredentialLeases.status, "issuing"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (finalized.length !== 1) throw new Error("lease issuance claim was lost");
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: claim.id,
        tenantId: input.tenantId,
        action: "lease.delivery_pending",
        decision: "allow",
        metadata: {
          workspaceId: input.workspaceId,
          agentId: input.agentId,
          grantId: input.resolved.grant.id,
          resourceHash: resourceHash(resource),
        },
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: claim.id,
          action: "upstream_credential_lease.delivery_pending",
          actorType: "agent",
          actorId: input.agentId,
          metadata: {
            workspaceId: input.workspaceId,
            grantId: input.resolved.grant.id,
            capabilityId: input.resolved.capability.id,
            resourceHash: resourceHash(resource),
          },
        }),
      );
    });
    if (authorityInvalidated) {
      const revoked = await input.issuer.revoke(issued.token).then(
        () => true,
        () => false,
      );
      if (revoked) {
        await recordFailure(
          input.auditedTransaction,
          claim.id,
          input.tenantId,
          "lease authority changed during upstream issuance",
          "failed",
        );
      } else {
        await recordRecoverableSealedFailure({
          db: input.db,
          auditedTransaction: input.auditedTransaction,
          leaseId: claim.id,
          tenantId: input.tenantId,
          token: issued.token,
          sealed,
          expiresAt: issued.expiresAt,
          error: "lease authority changed during upstream issuance; revocation outcome unknown",
          now: new Date(),
        });
      }
      return {
        ok: false,
        status: 409,
        code: "lease_authority_changed",
        error: "grant or capability changed during credential issuance",
      };
    }
  } catch {
    // The token only exists in this frame. If durable finalization fails, revoke
    // it before dropping the reference; a hard kill inside this tiny boundary is
    // the documented provider-lifetime precommit-orphan case.
    const revoked = await input.issuer.revoke(issued.token).then(
      () => true,
      () => false,
    );
    if (revoked) {
      await recordFailure(
        input.auditedTransaction,
        claim.id,
        input.tenantId,
        "durable finalization failed",
        "failed",
      ).catch(() =>
        persistPendingSealedRevocation({
          db: input.db,
          leaseId: claim.id,
          tenantId: input.tenantId,
          token: issued.token,
          sealed,
          expiresAt: issued.expiresAt,
          error: "provider revoked; durable audit confirmation pending",
          now: new Date(),
        }),
      );
    } else {
      await recordRecoverableSealedFailure({
        db: input.db,
        auditedTransaction: input.auditedTransaction,
        leaseId: claim.id,
        tenantId: input.tenantId,
        token: issued.token,
        sealed,
        expiresAt: issued.expiresAt,
        error: "durable finalization failed; revocation outcome unknown",
        now: new Date(),
      }).catch(() =>
        persistPendingSealedRevocation({
          db: input.db,
          leaseId: claim.id,
          tenantId: input.tenantId,
          token: issued.token,
          sealed,
          expiresAt: issued.expiresAt,
          error: "durable audit unavailable; exact provider revocation pending",
          now: new Date(),
        }),
      );
    }
    return {
      ok: false,
      status: 503,
      code: "lease_finalization_failed",
      error: "credential delivery was aborted",
    };
  }

  return {
    ok: true,
    leaseId: claim.id,
    token: issued.token,
    expiresAt: issued.expiresAt.toISOString(),
    resource,
  };
}

export async function acknowledgeUpstreamCredentialLease(input: {
  db: Db;
  tenantId: string;
  agentId: string;
  leaseId: string;
  token: string;
  auditedTransaction: LeaseAuditedTransaction;
  now?: Date;
}): Promise<{ ok: true } | { ok: false; status: 403 | 404 | 409 | 503; error: string }> {
  const now = input.now ?? new Date();
  const [lease] = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      and(
        eq(upstreamCredentialLeases.id, input.leaseId),
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        eq(upstreamCredentialLeases.agentId, input.agentId),
      ),
    );
  if (!lease) return { ok: false, status: 404, error: "lease not found" };
  if (lease.status !== "delivery_pending") {
    return { ok: false, status: 409, error: "lease is not awaiting delivery acknowledgement" };
  }
  const acknowledgementCutoff = new Date(now.getTime() - DELIVERY_ACK_TIMEOUT_MS);
  if (
    lease.updatedAt.getTime() <= acknowledgementCutoff.getTime() ||
    !lease.expiresAt ||
    lease.expiresAt.getTime() <= now.getTime()
  ) {
    return { ok: false, status: 409, error: "lease delivery acknowledgement window expired" };
  }
  if (!equalHash(lease.tokenHash, input.token)) {
    return { ok: false, status: 403, error: "lease token proof does not match" };
  }
  const [claimed] = await input.db
    .update(upstreamCredentialLeases)
    .set({ status: "acknowledging", updatedAt: now })
    .where(
      and(
        eq(upstreamCredentialLeases.id, lease.id),
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        eq(upstreamCredentialLeases.agentId, input.agentId),
        eq(upstreamCredentialLeases.status, "delivery_pending"),
        eq(upstreamCredentialLeases.updatedAt, lease.updatedAt),
        gt(upstreamCredentialLeases.updatedAt, acknowledgementCutoff),
        isNotNull(upstreamCredentialLeases.expiresAt),
        gt(upstreamCredentialLeases.expiresAt, now),
      ),
    )
    .returning({ id: upstreamCredentialLeases.id });
  if (!claimed) return { ok: false, status: 409, error: "delivery acknowledgement raced" };
  try {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const activated = await tx
        .update(upstreamCredentialLeases)
        .set({ status: "active", deliveredAt: now, updatedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.agentId, input.agentId),
            eq(upstreamCredentialLeases.status, "acknowledging"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (activated.length !== 1) throw new Error("delivery acknowledgement claim was lost");
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: lease.id,
        tenantId: input.tenantId,
        action: "lease.issue",
        decision: "allow",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: lease.id,
          action: "upstream_credential_lease.activated",
          actorType: "agent",
          actorId: input.agentId,
          metadata: { workspaceId: lease.workspaceId, grantId: lease.grantId },
        }),
      );
    });
  } catch {
    await input.db
      .update(upstreamCredentialLeases)
      .set({ status: "delivery_pending", updatedAt: lease.updatedAt })
      .where(
        and(
          eq(upstreamCredentialLeases.id, lease.id),
          eq(upstreamCredentialLeases.tenantId, input.tenantId),
          eq(upstreamCredentialLeases.agentId, input.agentId),
          eq(upstreamCredentialLeases.status, "acknowledging"),
        ),
      )
      .catch(() => {});
    return { ok: false, status: 503, error: "credential acknowledgement could not be recorded" };
  }
  return { ok: true };
}

function equalHash(left: string | null, token: string): boolean {
  if (!left || !/^[a-f0-9]{64}$/.test(left)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(sha256(token), "hex"));
}

export async function revokeUpstreamCredentialLease(input: {
  db: Db;
  tenantId: string;
  agentId: string;
  leaseId: string;
  token: string;
  issuer: UpstreamTokenIssuer;
  auditedTransaction: LeaseAuditedTransaction;
  now?: Date;
}): Promise<{ ok: true } | { ok: false; status: 403 | 404 | 409 | 503; error: string }> {
  const now = input.now ?? new Date();
  const [lease] = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      and(
        eq(upstreamCredentialLeases.id, input.leaseId),
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        eq(upstreamCredentialLeases.agentId, input.agentId),
      ),
    );
  if (!lease) return { ok: false, status: 404, error: "lease not found" };
  if (
    lease.status !== "active" &&
    lease.status !== "delivery_pending" &&
    lease.status !== "acknowledging" &&
    lease.status !== "needs_attention" &&
    lease.status !== "revoking"
  ) {
    return { ok: false, status: 409, error: "lease is not active" };
  }
  if (
    lease.status === "active" &&
    lease.expiresAt &&
    new Date(lease.expiresAt).getTime() <= now.getTime()
  ) {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const expired = await tx
        .update(upstreamCredentialLeases)
        .set({ status: "expired", updatedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.status, "active"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (expired.length === 0) return;
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: lease.id,
        tenantId: input.tenantId,
        action: "lease.expire",
        decision: "allow",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: lease.id,
          action: "upstream_credential_lease.expired",
          actorType: "agent",
          actorId: input.agentId,
        }),
      );
    });
    return { ok: false, status: 409, error: "lease is expired" };
  }
  if (!equalHash(lease.tokenHash, input.token))
    return { ok: false, status: 403, error: "lease token proof does not match" };
  const claimCutoff = new Date(now.getTime() - REVOCATION_CLAIM_TIMEOUT_MS);
  const [claimed] = await input.db
    .update(upstreamCredentialLeases)
    .set({ status: "revoking", updatedAt: now })
    .where(
      lease.status === "active" ||
        lease.status === "delivery_pending" ||
        lease.status === "acknowledging" ||
        lease.status === "needs_attention"
        ? and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, lease.status),
          )
        : and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, "revoking"),
            lte(upstreamCredentialLeases.updatedAt, claimCutoff),
          ),
    )
    .returning({ id: upstreamCredentialLeases.id });
  if (!claimed) return { ok: false, status: 409, error: "lease is not active" };
  try {
    await input.issuer.revoke(input.token);
  } catch {
    await input
      .auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
        const changed = await tx
          .update(upstreamCredentialLeases)
          .set({
            status: "needs_attention",
            lastError: "upstream revoker outcome unknown",
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(upstreamCredentialLeases.id, lease.id),
              eq(upstreamCredentialLeases.tenantId, input.tenantId),
              eq(upstreamCredentialLeases.status, "revoking"),
            ),
          )
          .returning({ id: upstreamCredentialLeases.id });
        if (changed.length === 0) return;
        await tx.insert(upstreamCredentialLeaseEvents).values({
          leaseId: lease.id,
          tenantId: input.tenantId,
          action: "lease.revoke",
          decision: "deny",
          metadata: { reason: "upstream revoker failed" },
        });
        await appendRequiredAudit(
          coreAuditEvent({
            tenantId: input.tenantId,
            leaseId: lease.id,
            action: "upstream_credential_lease.needs_attention",
            actorType: "agent",
            actorId: input.agentId,
            metadata: { reason: "upstream revoker outcome unknown" },
          }),
        );
      })
      .catch(() => {
        // A durable revoking claim is recoverable after the bounded claim
        // timeout; never claim that the provider token is active or revoked.
      });
    return { ok: false, status: 503, error: "upstream credential revoker unavailable" };
  }
  try {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const finalized = await tx
        .update(upstreamCredentialLeases)
        .set({ status: "revoked", revokedAt: now, lastError: null, updatedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (finalized.length !== 1) throw new Error("lease revocation claim was lost");
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: lease.id,
        tenantId: input.tenantId,
        action: "lease.revoke",
        decision: "allow",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: lease.id,
          action: "upstream_credential_lease.revoked",
          actorType: "agent",
          actorId: input.agentId,
        }),
      );
    });
  } catch {
    return {
      ok: false,
      status: 503,
      error: "upstream credential was revoked but durable confirmation failed; retry later",
    };
  }
  return { ok: true };
}

function sealedTokenFromLease(lease: any): SealedLeaseToken | null {
  if (!lease.tokenCiphertext || !lease.tokenIv || !lease.tokenAuthTag || !lease.tokenSalt) {
    return null;
  }
  return {
    ciphertext: lease.tokenCiphertext,
    iv: lease.tokenIv,
    tag: lease.tokenAuthTag,
    salt: lease.tokenSalt,
  };
}

async function revokeExactSealedLease(input: {
  db: Db;
  tenantId: string;
  lease: any;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  now: Date;
  mode?: "authority_teardown" | "stale_recovery";
  staleCutoff?: Date;
}): Promise<{ ok: true; revoked: number } | { ok: false; error: string }> {
  const sealed = sealedTokenFromLease(input.lease);
  if (!sealed) {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const exactPredicate =
        input.mode === "stale_recovery"
          ? and(
              eq(upstreamCredentialLeases.status, input.lease.status),
              eq(upstreamCredentialLeases.updatedAt, input.lease.updatedAt),
              lte(
                upstreamCredentialLeases.updatedAt,
                input.staleCutoff ?? new Date(input.now.getTime() - REVOCATION_CLAIM_TIMEOUT_MS),
              ),
            )
          : or(
              eq(upstreamCredentialLeases.status, "active"),
              eq(upstreamCredentialLeases.status, "delivery_pending"),
              eq(upstreamCredentialLeases.status, "acknowledging"),
              eq(upstreamCredentialLeases.status, "needs_attention"),
              eq(upstreamCredentialLeases.status, "revoking"),
            );
      const changed = await tx
        .update(upstreamCredentialLeases)
        .set({
          status: "needs_attention",
          lastError: "revocation handle unavailable",
          updatedAt: input.now,
        })
        .where(
          and(
            eq(upstreamCredentialLeases.id, input.lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            exactPredicate,
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (changed.length === 0) return;
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: input.lease.id,
        tenantId: input.tenantId,
        action: "lease.revocation_handle_missing",
        decision: "deny",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: input.lease.id,
          action: "upstream_credential_lease.needs_attention",
          metadata: { reason: "revocation handle unavailable" },
        }),
      );
    });
    return { ok: false, error: "upstream credential requires operator attention" };
  }
  const claimable = ["active", "delivery_pending", "acknowledging", "needs_attention"];
  const claimCutoff = new Date(input.now.getTime() - REVOCATION_CLAIM_TIMEOUT_MS);
  const claimPredicate =
    input.mode === "stale_recovery"
      ? and(
          eq(upstreamCredentialLeases.status, input.lease.status),
          eq(upstreamCredentialLeases.updatedAt, input.lease.updatedAt),
          lte(upstreamCredentialLeases.updatedAt, input.staleCutoff ?? claimCutoff),
        )
      : or(
          ...claimable.map((status) => eq(upstreamCredentialLeases.status, status)),
          and(
            eq(upstreamCredentialLeases.status, "revoking"),
            lte(upstreamCredentialLeases.updatedAt, claimCutoff),
          ),
        );
  const [claimed] = await input.db
    .update(upstreamCredentialLeases)
    .set({ status: "revoking", updatedAt: input.now })
    .where(
      and(
        eq(upstreamCredentialLeases.id, input.lease.id),
        eq(upstreamCredentialLeases.tenantId, input.tenantId),
        claimPredicate,
      ),
    )
    .returning({ id: upstreamCredentialLeases.id });
  if (!claimed) {
    return input.mode === "stale_recovery"
      ? { ok: true, revoked: 0 }
      : { ok: false, error: "upstream credential revocation raced" };
  }
  try {
    await input.exerciseToken(input.tenantId, input.lease.id, sealed, (token) =>
      input.issuer.revoke(token),
    );
  } catch {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const changed = await tx
        .update(upstreamCredentialLeases)
        .set({
          status: "needs_attention",
          lastError: "authority revocation outcome unknown",
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(upstreamCredentialLeases.id, input.lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (changed.length === 0) return;
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: input.lease.id,
        tenantId: input.tenantId,
        action: "lease.authority_revoke",
        decision: "deny",
        metadata: { reason: "provider outcome unknown" },
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: input.lease.id,
          action: "upstream_credential_lease.needs_attention",
          metadata: { reason: "provider revocation outcome unknown" },
        }),
      );
    });
    return { ok: false, error: "upstream credential revocation is incomplete" };
  }
  try {
    await input.auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
      const finalized = await tx
        .update(upstreamCredentialLeases)
        .set({ status: "revoked", revokedAt: input.now, lastError: null, updatedAt: input.now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, input.lease.id),
            eq(upstreamCredentialLeases.tenantId, input.tenantId),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        )
        .returning({ id: upstreamCredentialLeases.id });
      if (finalized.length !== 1) throw new Error("lease revocation claim was lost");
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: input.lease.id,
        tenantId: input.tenantId,
        action: "lease.authority_revoke",
        decision: "allow",
      });
      await appendRequiredAudit(
        coreAuditEvent({
          tenantId: input.tenantId,
          leaseId: input.lease.id,
          action: "upstream_credential_lease.authority_revoked",
          metadata: { grantId: input.lease.grantId, capabilityId: input.lease.capabilityId },
        }),
      );
    });
  } catch {
    // The provider may already have invalidated the token. Preserve an honest,
    // recoverable state and let the idempotent exact-token revoker reconcile it.
    await input
      .auditedTransaction(input.tenantId, async (tx: Db, appendRequiredAudit) => {
        const changed = await tx
          .update(upstreamCredentialLeases)
          .set({
            status: "needs_attention",
            lastError: "provider revoked; durable confirmation incomplete",
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(upstreamCredentialLeases.id, input.lease.id),
              eq(upstreamCredentialLeases.tenantId, input.tenantId),
              eq(upstreamCredentialLeases.status, "revoking"),
            ),
          )
          .returning({ id: upstreamCredentialLeases.id });
        if (changed.length === 0) return;
        await tx.insert(upstreamCredentialLeaseEvents).values({
          leaseId: input.lease.id,
          tenantId: input.tenantId,
          action: "lease.authority_revoke",
          decision: "deny",
          metadata: { reason: "provider revoked; durable confirmation incomplete" },
        });
        await appendRequiredAudit(
          coreAuditEvent({
            tenantId: input.tenantId,
            leaseId: input.lease.id,
            action: "upstream_credential_lease.needs_attention",
            metadata: { reason: "provider revoked; durable confirmation incomplete" },
          }),
        );
      })
      .catch(() => {});
    return { ok: false, error: "upstream credential revocation confirmation is incomplete" };
  }
  return { ok: true, revoked: 1 };
}

/** Revoke every provider token bound to authority that is being revoked or
 * changed. Provider failures are durable `needs_attention` outcomes and make the
 * operator mutation fail closed so authority cannot appear fully revoked while
 * a known-live credential remains usable. */
export async function revokeUpstreamLeasesForAuthority(input: {
  db: Db;
  tenantId: string;
  issuer: UpstreamTokenIssuer;
  exerciseToken: ExerciseLeaseToken;
  auditedTransaction: LeaseAuditedTransaction;
  grantId?: string;
  capabilityId?: string;
  now?: Date;
}): Promise<{ ok: true; revoked: number } | { ok: false; error: string }> {
  if (!input.grantId && !input.capabilityId)
    return { ok: false, error: "authority binding required" };
  const bindings = [eq(upstreamCredentialLeases.tenantId, input.tenantId)];
  if (input.grantId) bindings.push(eq(upstreamCredentialLeases.grantId, input.grantId));
  if (input.capabilityId)
    bindings.push(eq(upstreamCredentialLeases.capabilityId, input.capabilityId));
  const leases = await input.db
    .select()
    .from(upstreamCredentialLeases)
    .where(
      and(
        ...bindings,
        or(
          eq(upstreamCredentialLeases.status, "active"),
          eq(upstreamCredentialLeases.status, "delivery_pending"),
          eq(upstreamCredentialLeases.status, "acknowledging"),
          eq(upstreamCredentialLeases.status, "needs_attention"),
          eq(upstreamCredentialLeases.status, "revoking"),
        ),
      ),
    );
  let revoked = 0;
  let firstError: string | undefined;
  for (const lease of leases) {
    const now = input.now ?? new Date();
    let result: Awaited<ReturnType<typeof revokeExactSealedLease>>;
    try {
      result = await revokeExactSealedLease({
        ...input,
        lease,
        now,
        mode: "authority_teardown",
      });
    } catch (error) {
      firstError ??= error instanceof Error ? error.message : "lease revocation persistence failed";
      continue;
    }
    if (!result.ok) {
      firstError ??= result.error;
      continue;
    }
    revoked += result.revoked;
  }
  if (firstError) return { ok: false, error: firstError };
  return { ok: true, revoked };
}
