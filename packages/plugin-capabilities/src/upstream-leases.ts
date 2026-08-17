import { createHash, timingSafeEqual } from "node:crypto";
import {
  and,
  asc,
  eq,
  lte,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
} from "@stwd/db";

export const GITHUB_APP_LEASE_ISSUER = "github-app-installation";
export const MAX_UPSTREAM_LEASE_TTL_SECONDS = 3600;
const MIN_UPSTREAM_LEASE_TTL_SECONDS = 60;

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
    ttlSeconds: number;
  }): Promise<{ token: string; expiresAt: Date }>;
  revoke(token: string): Promise<void>;
}

export type ExerciseCredentialSecret = <T>(
  tenantId: string,
  secretId: string,
  use: (plaintext: string) => Promise<T>,
) => Promise<T>;

type Db = any;

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

function canonicalResource(resource: GitHubLeaseResource): GitHubLeaseResource {
  const repositories = [...new Set(resource.repositories.map((value) => value.trim()))].sort();
  const permissions = Object.fromEntries(
    Object.entries(resource.permissions)
      .map(([key, value]) => [key.trim(), value] as const)
      .sort(([a], [b]) => a.localeCompare(b)),
  );
  return { repositories, permissions };
}

function resourceHash(resource: GitHubLeaseResource): string {
  return sha256(JSON.stringify(canonicalResource(resource)));
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
  if (
    maxTtlSeconds !== undefined &&
    (!Number.isInteger(maxTtlSeconds) ||
      (maxTtlSeconds as number) < MIN_UPSTREAM_LEASE_TTL_SECONDS ||
      (maxTtlSeconds as number) > MAX_UPSTREAM_LEASE_TTL_SECONDS)
  ) {
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
  const normalized = canonicalResource(requested);
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
  db: Db,
  leaseId: string,
  tenantId: string,
  error: string,
): Promise<void> {
  await db.transaction(async (tx: Db) => {
    await tx
      .update(upstreamCredentialLeases)
      .set({ status: "failed", lastError: error.slice(0, 500), updatedAt: new Date() })
      .where(eq(upstreamCredentialLeases.id, leaseId));
    await tx.insert(upstreamCredentialLeaseEvents).values({
      leaseId,
      tenantId,
      action: "lease.issue",
      decision: "deny",
      metadata: { reason: error.slice(0, 200) },
    });
  });
}

/** Bounded durable expiry sweep. Issuance invokes it opportunistically; a host
 * may also schedule it directly when no new leases are being requested. */
export async function expireUpstreamCredentialLeases(input: {
  db: Db;
  tenantId: string;
  now?: Date;
  limit?: number;
}): Promise<number> {
  const now = input.now ?? new Date();
  const limit = Math.max(1, Math.min(input.limit ?? 100, 500));
  return input.db.transaction(async (tx: Db) => {
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
    }
    return expired;
  });
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
  issuer: UpstreamTokenIssuer;
  now?: Date;
}): Promise<LeaseIssueResult> {
  try {
    await expireUpstreamCredentialLeases({
      db: input.db,
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
  const maxTtl = Math.min(
    config.maxTtlSeconds ?? MAX_UPSTREAM_LEASE_TTL_SECONDS,
    MAX_UPSTREAM_LEASE_TTL_SECONDS,
  );
  if (
    !Number.isInteger(input.ttlSeconds) ||
    input.ttlSeconds < MIN_UPSTREAM_LEASE_TTL_SECONDS ||
    input.ttlSeconds > maxTtl
  ) {
    return {
      ok: false,
      status: 400,
      code: "ttl_out_of_range",
      error: `ttlSeconds must be ${MIN_UPSTREAM_LEASE_TTL_SECONDS}-${maxTtl}`,
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
  const [claim] = await input.db
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
      idempotencyKeyHash: sha256(input.idempotencyKey),
      status: "issuing",
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoNothing()
    .returning({ id: upstreamCredentialLeases.id });
  if (!claim) {
    return {
      ok: false,
      status: 409,
      code: "lease_replay",
      error: "this issuance key was already consumed; credentials are never replayed",
    };
  }

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
          ttlSeconds: input.ttlSeconds,
        }),
    );
  } catch {
    await recordFailure(input.db, claim.id, input.tenantId, "upstream issuer failed");
    return {
      ok: false,
      status: 503,
      code: "issuer_unavailable",
      error: "upstream credential issuer unavailable",
    };
  }

  // GitHub currently chooses installation-token expiry. Never pretend a locally
  // requested shorter TTL constrains a credential that remains live upstream.
  if (
    !issued.token ||
    !Number.isFinite(issued.expiresAt.getTime()) ||
    issued.expiresAt.getTime() <= now.getTime() ||
    issued.expiresAt.getTime() > now.getTime() + input.ttlSeconds * 1000 + 30_000
  ) {
    await input.issuer.revoke(issued.token).catch(() => {});
    await recordFailure(
      input.db,
      claim.id,
      input.tenantId,
      "upstream expiry exceeded requested ttl",
    );
    return {
      ok: false,
      status: 503,
      code: "issuer_contract_violation",
      error: "upstream issuer returned an invalid expiry",
    };
  }

  try {
    await input.db.transaction(async (tx: Db) => {
      await tx
        .update(upstreamCredentialLeases)
        .set({
          tokenHash: sha256(issued.token),
          status: "active",
          expiresAt: issued.expiresAt,
          deliveredAt: now,
          updatedAt: now,
        })
        .where(
          and(
            eq(upstreamCredentialLeases.id, claim.id),
            eq(upstreamCredentialLeases.status, "issuing"),
          ),
        );
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: claim.id,
        tenantId: input.tenantId,
        action: "lease.issue",
        decision: "allow",
        metadata: {
          workspaceId: input.workspaceId,
          agentId: input.agentId,
          grantId: input.resolved.grant.id,
          resourceHash: resourceHash(resource),
        },
      });
    });
  } catch {
    // The token only exists in this frame. If durable finalization fails, revoke
    // it before dropping the reference; a hard kill inside this tiny boundary is
    // the documented provider-lifetime precommit-orphan case.
    const revoked = await input.issuer.revoke(issued.token).then(
      () => true,
      () => false,
    );
    await input.db
      .update(upstreamCredentialLeases)
      .set({
        status: revoked ? "failed" : "needs_attention",
        lastError: "durable finalization failed",
        updatedAt: new Date(),
      })
      .where(eq(upstreamCredentialLeases.id, claim.id))
      .catch(() => {});
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
  if (lease.status !== "active") return { ok: false, status: 409, error: "lease is not active" };
  if (lease.expiresAt && new Date(lease.expiresAt).getTime() <= now.getTime()) {
    await input.db.transaction(async (tx: Db) => {
      await tx
        .update(upstreamCredentialLeases)
        .set({ status: "expired", updatedAt: now })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.status, "active"),
          ),
        );
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: lease.id,
        tenantId: input.tenantId,
        action: "lease.expire",
        decision: "allow",
      });
    });
    return { ok: false, status: 409, error: "lease is expired" };
  }
  if (!equalHash(lease.tokenHash, input.token))
    return { ok: false, status: 403, error: "lease token proof does not match" };
  const [claimed] = await input.db
    .update(upstreamCredentialLeases)
    .set({ status: "revoking", updatedAt: now })
    .where(
      and(eq(upstreamCredentialLeases.id, lease.id), eq(upstreamCredentialLeases.status, "active")),
    )
    .returning({ id: upstreamCredentialLeases.id });
  if (!claimed) return { ok: false, status: 409, error: "lease is not active" };
  try {
    await input.issuer.revoke(input.token);
  } catch {
    await input.db.transaction(async (tx: Db) => {
      await tx
        .update(upstreamCredentialLeases)
        .set({ status: "active", lastError: "upstream revoker failed", updatedAt: new Date() })
        .where(
          and(
            eq(upstreamCredentialLeases.id, lease.id),
            eq(upstreamCredentialLeases.status, "revoking"),
          ),
        );
      await tx.insert(upstreamCredentialLeaseEvents).values({
        leaseId: lease.id,
        tenantId: input.tenantId,
        action: "lease.revoke",
        decision: "deny",
        metadata: { reason: "upstream revoker failed" },
      });
    });
    return { ok: false, status: 503, error: "upstream credential revoker unavailable" };
  }
  await input.db.transaction(async (tx: Db) => {
    await tx
      .update(upstreamCredentialLeases)
      .set({ status: "revoked", revokedAt: now, lastError: null, updatedAt: now })
      .where(
        and(
          eq(upstreamCredentialLeases.id, lease.id),
          eq(upstreamCredentialLeases.status, "revoking"),
        ),
      );
    await tx.insert(upstreamCredentialLeaseEvents).values({
      leaseId: lease.id,
      tenantId: input.tenantId,
      action: "lease.revoke",
      decision: "allow",
    });
  });
  return { ok: true };
}
