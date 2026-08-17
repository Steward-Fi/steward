import { randomUUID } from "node:crypto";
import {
  agents,
  getDb,
  providerAccounts,
  providerAuthorityTenantState,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  userTenants,
  workspaces,
} from "@stwd/db";
import {
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  genericDescriptorAllowsExactPath,
  genericDescriptorGovernedRoutePattern,
  PROVIDER_ACCESS_REASON,
  type ProviderAccessDecisionV1,
  type ProviderAccessRequestV1,
  type ProviderAuthorityMutationContext,
  type ProviderEnvironment,
  type ProviderPrincipalType,
  type ProviderRiskClass,
  secretRouteHostPatternsOverlap,
  secretRouteMethodPatternsOverlap,
  secretRoutePathPatternsOverlap,
  validateGenericHttpDescriptor,
} from "@stwd/shared";
import { and, eq, inArray, sql } from "drizzle-orm";
import {
  assertNoOppositeAuthorityOverlap,
  lockSecretRouteNamespaces,
  SecretRouteAuthorityConflict,
} from "./secret-route-authority";

const RECENT_MFA_MS = 5 * 60_000;
const OPERATION_KEY = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+$/;
const KEY = /^[a-z][a-z0-9_-]{0,127}$/;
const PROVIDER_OPERATION_ALLOWLIST: Readonly<
  Record<string, Readonly<Record<string, "GET" | "POST" | "DELETE">>>
> = {
  github: {
    "github.issue.list": "GET",
    "github.pr.comment.create": "POST",
  },
  x: {
    "x.tweet.create": "POST",
    "x.tweet.delete": "DELETE",
    "x.user.me.read": "GET",
  },
};
const PROVIDER_HOST_ALLOWLIST: Readonly<Record<string, string>> = {
  github: "api.github.com",
  x: "api.x.com",
};
const REGISTERED_ADAPTER_KEYS = new Set(["github", "x", "generic-http"]);
const ENVIRONMENTS = new Set(["development", "staging", "production"]);
const PRINCIPAL_TYPES = new Set(["human", "agent"]);
const ROLES = new Set([
  "tenant_authority_admin",
  "workspace_admin",
  "workspace_operator",
  "workspace_viewer",
  "workspace_approver",
]);
const RISK_CLASSES = new Set(["read", "write", "consequential"]);

export class ProviderAuthorityError extends Error {
  constructor(
    message: string,
    readonly code:
      | "bad_request"
      | "forbidden"
      | "not_found"
      | "revision_conflict"
      | "last_admin"
      | "audit_required",
    readonly status: 400 | 403 | 404 | 409 | 428,
  ) {
    super(message);
  }
}

export type AuthorityAudit = (event: {
  action: string;
  resourceType: string;
  resourceId?: string;
  metadata: Record<string, unknown>;
}) => Promise<void>;

type MutationContext = ProviderAuthorityMutationContext & { audit: AuthorityAudit };
type BindingInsert = typeof providerRoleBindings.$inferInsert;
type GrantInsert = typeof providerGrants.$inferInsert;

function assertText(value: unknown, field: string, max = 512): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized || normalized.length > max) {
    throw new ProviderAuthorityError(
      `${field} is required and must be at most ${max} characters`,
      "bad_request",
      400,
    );
  }
  return normalized;
}

function assertMutationContext(ctx: MutationContext): void {
  assertText(ctx.reason, "reason", 2_000);
  if (!ctx.idempotencyKey || ctx.idempotencyKey.length < 8) {
    throw new ProviderAuthorityError("Idempotency-Key is required", "bad_request", 400);
  }
  if (!Number.isInteger(ctx.expectedRevision) || ctx.expectedRevision < 0) {
    throw new ProviderAuthorityError(
      "expectedRevision must be a non-negative integer",
      "bad_request",
      400,
    );
  }
  if (
    !Number.isFinite(ctx.mfaVerifiedAt) ||
    Date.now() - ctx.mfaVerifiedAt > RECENT_MFA_MS ||
    ctx.mfaVerifiedAt > Date.now() + 30_000
  ) {
    throw new ProviderAuthorityError("recent MFA verification is required", "forbidden", 403);
  }
  if (typeof ctx.audit !== "function") {
    throw new ProviderAuthorityError("mandatory audit writer is required", "audit_required", 428);
  }
}

function activeAt(
  row: {
    status: string;
    notBefore?: Date | null;
    expiresAt?: Date | null;
    environment?: string | null;
  },
  now: Date,
  environment: string,
): boolean {
  return (
    row.status === "active" &&
    (!row.notBefore || row.notBefore <= now) &&
    (!row.expiresAt || row.expiresAt > now) &&
    (!row.environment || row.environment === environment)
  );
}

function operationIncluded(keys: string[], operationKey: string): boolean {
  return keys.includes(operationKey);
}

function subset(candidate: string[], allowed: string[]): boolean {
  const set = new Set(allowed);
  return candidate.every((key) => set.has(key));
}

export class ProviderAuthorityStore {
  private db() {
    return getDb();
  }

  private async membership(tenantId: string, userId: string) {
    const [row] = await this.db()
      .select()
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, userId)))
      .limit(1);
    return row;
  }

  private async activeTenantAdmins(tenantId: string, at = new Date()) {
    const rows = await this.db()
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.roleKey, "tenant_authority_admin"),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    return rows.filter(
      (row) => (!row.notBefore || row.notBefore <= at) && (!row.expiresAt || row.expiresAt > at),
    );
  }

  /** Owner compatibility is bootstrap-only. Creating the first explicit tenant admin closes it permanently. */
  private async hasTenantAdmin(
    ctx: Pick<MutationContext, "tenantId" | "actorUserId" | "tenantRole">,
  ): Promise<boolean> {
    const membership = await this.membership(ctx.tenantId, ctx.actorUserId);
    if (!membership) return false;
    const explicit = await this.activeTenantAdmins(ctx.tenantId);
    if (
      explicit.some((row) => row.principalType === "human" && row.principalId === ctx.actorUserId)
    )
      return true;
    await this.ensureTenantState(ctx.tenantId);
    const [state] = await this.db()
      .select({ bootstrapCompleted: providerAuthorityTenantState.bootstrapCompleted })
      .from(providerAuthorityTenantState)
      .where(eq(providerAuthorityTenantState.tenantId, ctx.tenantId))
      .limit(1);
    return !state?.bootstrapCompleted && membership.role === "owner" && ctx.tenantRole === "owner";
  }

  private async workspaceAdminMandate(
    tenantId: string,
    workspaceId: string,
    userId: string,
    at = new Date(),
  ) {
    const [workspace] = await this.db()
      .select({ environment: workspaces.environment })
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, workspaceId)))
      .limit(1);
    if (!workspace) return undefined;
    const rows = await this.db()
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.workspaceId, workspaceId),
          eq(providerRoleBindings.principalType, "human"),
          eq(providerRoleBindings.principalId, userId),
          eq(providerRoleBindings.roleKey, "workspace_admin"),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    return rows.find((row) => activeAt(row, at, workspace.environment));
  }

  private async requireWorkspaceAdmin(
    ctx: MutationContext,
    workspaceId: string,
    allowTenantAdmin: boolean,
  ) {
    if (allowTenantAdmin && (await this.hasTenantAdmin(ctx)))
      return { type: "tenant" as const, operationKeys: [] as string[] };
    const binding = await this.workspaceAdminMandate(ctx.tenantId, workspaceId, ctx.actorUserId);
    if (!binding) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    return { type: "workspace" as const, operationKeys: binding.operationKeys };
  }

  private async ensureTenantState(tenantId: string): Promise<number> {
    await this.db()
      .insert(providerAuthorityTenantState)
      .values({ tenantId, revision: 0 })
      .onConflictDoNothing();
    const [row] = await this.db()
      .select()
      .from(providerAuthorityTenantState)
      .where(eq(providerAuthorityTenantState.tenantId, tenantId));
    return row?.revision ?? 0;
  }

  async canAdminister(
    tenantId: string,
    workspaceId: string | undefined,
    userId: string,
    tenantRole: string,
  ): Promise<boolean> {
    const ctx = { tenantId, actorUserId: userId, tenantRole };
    if (await this.hasTenantAdmin(ctx)) return true;
    return Boolean(
      workspaceId && (await this.workspaceAdminMandate(tenantId, workspaceId, userId)),
    );
  }

  async getTenantRevision(tenantId: string): Promise<number> {
    return this.ensureTenantState(tenantId);
  }

  /**
   * Provider-account CONNECT authority (issue #195 workstream A): a caller may
   * initiate/complete/disconnect an X (or other provider) OAuth connection when
   * they are a tenant authority admin OR hold an active workspace_admin /
   * workspace_approver binding for the target workspace (environment + temporal
   * validity enforced). Mirrors the admin-OR-approver gate of PR3's
   * hasWorkspaceRoleAuthority, scoped to the connect surface.
   */
  async canConnectProviderAccounts(
    tenantId: string,
    workspaceId: string,
    userId: string,
    tenantRole: string,
  ): Promise<boolean> {
    const ctx = { tenantId, actorUserId: userId, tenantRole };
    if (await this.hasTenantAdmin(ctx)) return true;
    if (!(await this.membership(tenantId, userId))) return false;
    const [workspace] = await this.db()
      .select({ environment: workspaces.environment, status: workspaces.status })
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, workspaceId)))
      .limit(1);
    if (!workspace || workspace.status !== "active") return false;
    const rows = await this.db()
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.workspaceId, workspaceId),
          eq(providerRoleBindings.principalType, "human"),
          eq(providerRoleBindings.principalId, userId),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    const now = new Date();
    return rows.some(
      (row) =>
        (row.roleKey === "workspace_admin" || row.roleKey === "workspace_approver") &&
        activeAt(row, now, workspace.environment),
    );
  }

  async createWorkspace(
    ctx: MutationContext,
    input: { key: string; name: string; environment: ProviderEnvironment },
  ) {
    assertMutationContext(ctx);
    if (!ENVIRONMENTS.has(input.environment))
      throw new ProviderAuthorityError("invalid environment", "bad_request", 400);
    if (!(await this.hasTenantAdmin(ctx)))
      throw new ProviderAuthorityError("tenant authority required", "forbidden", 403);
    const key = assertText(input.key, "key", 128);
    if (!KEY.test(key))
      throw new ProviderAuthorityError("invalid workspace key", "bad_request", 400);
    const current = await this.ensureTenantState(ctx.tenantId);
    if (current !== ctx.expectedRevision)
      throw new ProviderAuthorityError("authority revision conflict", "revision_conflict", 409);
    const id = randomUUID();
    await ctx.audit({
      action: "provider.workspace.create",
      resourceType: "workspace",
      resourceId: id,
      metadata: { expectedRevision: current, key, reason: ctx.reason },
    });
    return this.db().transaction(async (tx) => {
      const [cas] = await tx
        .update(providerAuthorityTenantState)
        .set({ revision: current + 1, updatedAt: new Date() })
        .where(
          and(
            eq(providerAuthorityTenantState.tenantId, ctx.tenantId),
            eq(providerAuthorityTenantState.revision, current),
          ),
        )
        .returning();
      if (!cas)
        throw new ProviderAuthorityError("authority revision conflict", "revision_conflict", 409);
      const [row] = await tx
        .insert(workspaces)
        .values({
          id,
          tenantId: ctx.tenantId,
          key,
          name: assertText(input.name, "name", 255),
          environment: input.environment,
          createdBy: ctx.actorUserId,
        })
        .returning();
      return row;
    });
  }

  async listWorkspaces(tenantId: string) {
    return this.db().select().from(workspaces).where(eq(workspaces.tenantId, tenantId));
  }

  async disableWorkspace(ctx: MutationContext, id: string) {
    assertMutationContext(ctx);
    if (!(await this.hasTenantAdmin(ctx)))
      throw new ProviderAuthorityError("tenant authority required", "forbidden", 403);
    const [row] = await this.db()
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.id, id), eq(workspaces.tenantId, ctx.tenantId)))
      .limit(1);
    if (!row) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (row.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
    await ctx.audit({
      action: "provider.workspace.disable",
      resourceType: "workspace",
      resourceId: id,
      metadata: { expectedRevision: row.revision, reason: ctx.reason },
    });
    const [updated] = await this.db()
      .update(workspaces)
      .set({ status: "disabled", revision: row.revision + 1, updatedAt: new Date() })
      .where(
        and(
          eq(workspaces.id, id),
          eq(workspaces.tenantId, ctx.tenantId),
          eq(workspaces.revision, row.revision),
        ),
      )
      .returning();
    if (!updated)
      throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
    return updated;
  }

  async createProviderAccount(
    ctx: MutationContext,
    input: {
      workspaceId: string;
      adapterKey: string;
      externalRef: string;
      displayName: string;
      credentialSecretId?: string;
      credentialVersion?: number;
    },
  ) {
    assertMutationContext(ctx);
    await this.requireWorkspaceAdmin(ctx, input.workspaceId, true);
    const [workspace] = await this.db()
      .select()
      .from(workspaces)
      .where(
        and(
          eq(workspaces.id, input.workspaceId),
          eq(workspaces.tenantId, ctx.tenantId),
          eq(workspaces.status, "active"),
        ),
      )
      .limit(1);
    if (!workspace) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (workspace.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
    if (Boolean(input.credentialSecretId) !== Boolean(input.credentialVersion))
      throw new ProviderAuthorityError(
        "credentialSecretId and credentialVersion must be supplied together",
        "bad_request",
        400,
      );
    if (input.credentialSecretId) {
      if (ctx.tenantRole !== "owner" && ctx.tenantRole !== "admin") {
        throw new ProviderAuthorityError(
          "credential binding also requires the existing secret-management gate",
          "forbidden",
          403,
        );
      }
      const [secret] = await this.db()
        .select()
        .from(secrets)
        .where(
          and(
            eq(secrets.tenantId, ctx.tenantId),
            eq(secrets.id, input.credentialSecretId),
            eq(secrets.version, input.credentialVersion as number),
            sql`${secrets.deletedAt} IS NULL`,
          ),
        )
        .limit(1);
      if (!secret || (secret.expiresAt && secret.expiresAt <= new Date()))
        throw new ProviderAuthorityError("resource not found", "not_found", 404);
    }
    const adapterKey = assertText(input.adapterKey, "adapterKey", 128);
    if (!REGISTERED_ADAPTER_KEYS.has(adapterKey)) {
      throw new ProviderAuthorityError("adapter is not registered", "bad_request", 400);
    }
    const id = randomUUID();
    await ctx.audit({
      action: "provider.account.create",
      resourceType: "provider_account",
      resourceId: id,
      metadata: {
        workspaceId: workspace.id,
        expectedRevision: workspace.revision,
        reason: ctx.reason,
      },
    });
    return this.db().transaction(async (tx) => {
      const [cas] = await tx
        .update(workspaces)
        .set({ revision: workspace.revision + 1, updatedAt: new Date() })
        .where(
          and(
            eq(workspaces.id, workspace.id),
            eq(workspaces.tenantId, ctx.tenantId),
            eq(workspaces.revision, workspace.revision),
          ),
        )
        .returning();
      if (!cas)
        throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
      const [row] = await tx
        .insert(providerAccounts)
        .values({
          id,
          tenantId: ctx.tenantId,
          workspaceId: workspace.id,
          adapterKey,
          externalRef: assertText(input.externalRef, "externalRef", 512),
          displayName: assertText(input.displayName, "displayName", 255),
          credentialSecretId: input.credentialSecretId,
          credentialVersion: input.credentialVersion,
        })
        .returning();
      return row;
    });
  }

  async listProviderAccounts(tenantId: string, workspaceId?: string) {
    if (!workspaceId) return [];
    return this.db()
      .select()
      .from(providerAccounts)
      .where(
        and(eq(providerAccounts.tenantId, tenantId), eq(providerAccounts.workspaceId, workspaceId)),
      );
  }

  async disableProviderAccount(ctx: MutationContext, id: string) {
    assertMutationContext(ctx);
    const [row] = await this.db()
      .select()
      .from(providerAccounts)
      .where(and(eq(providerAccounts.id, id), eq(providerAccounts.tenantId, ctx.tenantId)))
      .limit(1);
    if (!row) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    await this.requireWorkspaceAdmin(ctx, row.workspaceId, true);
    if (row.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError(
        "provider account revision conflict",
        "revision_conflict",
        409,
      );
    await ctx.audit({
      action: "provider.account.disable",
      resourceType: "provider_account",
      resourceId: id,
      metadata: {
        workspaceId: row.workspaceId,
        expectedRevision: row.revision,
        reason: ctx.reason,
      },
    });
    const [updated] = await this.db()
      .update(providerAccounts)
      .set({ status: "disabled", revision: row.revision + 1, updatedAt: new Date() })
      .where(
        and(
          eq(providerAccounts.id, id),
          eq(providerAccounts.tenantId, ctx.tenantId),
          eq(providerAccounts.workspaceId, row.workspaceId),
          eq(providerAccounts.revision, row.revision),
        ),
      )
      .returning();
    if (!updated)
      throw new ProviderAuthorityError(
        "provider account revision conflict",
        "revision_conflict",
        409,
      );
    return updated;
  }

  async registerOperation(
    ctx: MutationContext,
    accountId: string,
    input: {
      operationKey: string;
      riskClass: ProviderRiskClass;
      capabilityId?: string;
      secretRouteId?: string;
      requestProfile?: Record<string, unknown>;
      responseProfile?: Record<string, unknown>;
    },
  ) {
    assertMutationContext(ctx);
    const [account] = await this.db()
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.id, accountId),
          eq(providerAccounts.tenantId, ctx.tenantId),
          eq(providerAccounts.status, "active"),
        ),
      )
      .limit(1);
    if (!account) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    await this.requireWorkspaceAdmin(ctx, account.workspaceId, true);
    if (account.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError(
        "provider account revision conflict",
        "revision_conflict",
        409,
      );
    const operationKey = assertText(input.operationKey, "operationKey", 128);
    if (!RISK_CLASSES.has(input.riskClass))
      throw new ProviderAuthorityError("invalid riskClass", "bad_request", 400);
    if (!OPERATION_KEY.test(operationKey))
      throw new ProviderAuthorityError("invalid operationKey", "bad_request", 400);
    let allowedMethods: readonly string[];
    let genericDescriptor: ReturnType<typeof validateGenericHttpDescriptor> | undefined;
    if (account.adapterKey === "generic-http") {
      try {
        if (input.requestProfile?.profile !== GENERIC_HTTP_PROVIDER_ACTION_PROFILE) {
          throw new Error("profile mismatch");
        }
        genericDescriptor = validateGenericHttpDescriptor(input.requestProfile.operationDescriptor);
        if (genericDescriptor.methods.length !== 1) {
          throw new Error("one route can bind exactly one method");
        }
        allowedMethods = genericDescriptor.methods;
      } catch {
        throw new ProviderAuthorityError(
          "invalid generic-http operation descriptor",
          "bad_request",
          400,
        );
      }
    } else {
      const fixedMethod = PROVIDER_OPERATION_ALLOWLIST[account.adapterKey]?.[operationKey];
      if (!fixedMethod)
        throw new ProviderAuthorityError(
          "operation is not in the adapter allowlist",
          "forbidden",
          403,
        );
      allowedMethods = [fixedMethod];
    }
    if (account.adapterKey === "generic-http" && !input.secretRouteId) {
      throw new ProviderAuthorityError(
        "generic-http operations require a governed credential route binding",
        "forbidden",
        403,
      );
    }
    if (input.secretRouteId) {
      const credentialSecretId = account.credentialSecretId;
      if (!credentialSecretId) {
        throw new ProviderAuthorityError(
          "provider account has no credential binding",
          "forbidden",
          403,
        );
      }
      const [route] = await this.db()
        .select()
        .from(secretRoutes)
        .where(
          and(
            eq(secretRoutes.tenantId, ctx.tenantId),
            eq(secretRoutes.id, input.secretRouteId),
            eq(secretRoutes.enabled, true),
          ),
        )
        .limit(1);
      const expectedHost = genericDescriptor
        ? new URL(genericDescriptor.origin).hostname
        : PROVIDER_HOST_ALLOWLIST[account.adapterKey];
      const method = route?.method?.toUpperCase();
      const pathAllowed = genericDescriptor
        ? Boolean(
            route?.pathPattern &&
              genericDescriptorAllowsExactPath(genericDescriptor, route.pathPattern),
          )
        : Boolean(route?.pathPattern && !route.pathPattern.includes("*"));
      if (
        !route ||
        route.secretId !== credentialSecretId ||
        !route.agentId ||
        route.authorityMode !== "legacy" ||
        route.providerOperationId !== null ||
        route.hostPattern !== expectedHost ||
        !method ||
        !allowedMethods.includes(method) ||
        !pathAllowed
      ) {
        throw new ProviderAuthorityError(
          "route target would widen the adapter operation",
          "forbidden",
          403,
        );
      }
      const promotedPath = genericDescriptor
        ? genericDescriptorGovernedRoutePattern(genericDescriptor)
        : route.pathPattern;
      // This early overlap check is only a fast rejection. The transaction below
      // repeats it after locking the agent's route namespace.
      const siblings = await this.db()
        .select()
        .from(secretRoutes)
        .where(
          and(
            eq(secretRoutes.tenantId, ctx.tenantId),
            eq(secretRoutes.agentId, route.agentId),
            eq(secretRoutes.enabled, true),
          ),
        );
      if (
        siblings.some(
          (candidate) =>
            candidate.id !== route.id &&
            secretRouteMethodPatternsOverlap(candidate.method, route.method) &&
            secretRouteHostPatternsOverlap(candidate.hostPattern, route.hostPattern) &&
            secretRoutePathPatternsOverlap(candidate.pathPattern ?? "/*", promotedPath ?? "/*"),
        )
      ) {
        throw new ProviderAuthorityError(
          "credential route overlaps another enabled route for this agent",
          "forbidden",
          403,
        );
      }
    }
    const id = randomUUID();
    await ctx.audit({
      action: "provider.operation.register",
      resourceType: "provider_operation",
      resourceId: id,
      metadata: {
        workspaceId: account.workspaceId,
        providerAccountId: account.id,
        operationKey,
        expectedRevision: account.revision,
        reason: ctx.reason,
      },
    });
    return this.db().transaction(async (tx) => {
      if (input.secretRouteId) {
        const [routeBeforeLock] = await tx
          .select()
          .from(secretRoutes)
          .where(
            and(
              eq(secretRoutes.tenantId, ctx.tenantId),
              eq(secretRoutes.id, input.secretRouteId),
              eq(secretRoutes.enabled, true),
            ),
          )
          .limit(1);
        if (!routeBeforeLock?.agentId) {
          throw new ProviderAuthorityError(
            "credential route changed during operation registration",
            "revision_conflict",
            409,
          );
        }
        await lockSecretRouteNamespaces(tx, ctx.tenantId, [routeBeforeLock.agentId]);
        const [route] = await tx
          .select()
          .from(secretRoutes)
          .where(
            and(
              eq(secretRoutes.tenantId, ctx.tenantId),
              eq(secretRoutes.id, input.secretRouteId),
              eq(secretRoutes.enabled, true),
            ),
          )
          .limit(1);
        const credentialSecretId = account.credentialSecretId;
        const expectedHost = genericDescriptor
          ? new URL(genericDescriptor.origin).hostname
          : PROVIDER_HOST_ALLOWLIST[account.adapterKey];
        const method = route?.method?.toUpperCase();
        const pathAllowed = genericDescriptor
          ? Boolean(
              route?.pathPattern &&
                genericDescriptorAllowsExactPath(genericDescriptor, route.pathPattern),
            )
          : Boolean(route?.pathPattern && !route.pathPattern.includes("*"));
        if (
          !credentialSecretId ||
          !route ||
          route.agentId !== routeBeforeLock.agentId ||
          route.secretId !== credentialSecretId ||
          route.authorityMode !== "legacy" ||
          route.providerOperationId !== null ||
          route.hostPattern !== expectedHost ||
          !method ||
          !allowedMethods.includes(method) ||
          !pathAllowed
        ) {
          throw new ProviderAuthorityError(
            "credential route changed during operation registration",
            "revision_conflict",
            409,
          );
        }
        try {
          await assertNoOppositeAuthorityOverlap(tx, {
            ...route,
            agentId: routeBeforeLock.agentId,
            authorityMode: "governed_v2",
            pathPattern: genericDescriptor
              ? genericDescriptorGovernedRoutePattern(genericDescriptor)
              : route.pathPattern,
          });
        } catch (error) {
          if (error instanceof SecretRouteAuthorityConflict) {
            throw new ProviderAuthorityError(error.message, "forbidden", 403);
          }
          throw error;
        }
      }
      const [cas] = await tx
        .update(providerAccounts)
        .set({ revision: account.revision + 1, updatedAt: new Date() })
        .where(
          and(
            eq(providerAccounts.id, account.id),
            eq(providerAccounts.tenantId, ctx.tenantId),
            eq(providerAccounts.workspaceId, account.workspaceId),
            eq(providerAccounts.revision, account.revision),
          ),
        )
        .returning();
      if (!cas)
        throw new ProviderAuthorityError(
          "provider account revision conflict",
          "revision_conflict",
          409,
        );
      const [row] = await tx
        .insert(providerOperations)
        .values({
          id,
          tenantId: ctx.tenantId,
          workspaceId: account.workspaceId,
          providerAccountId: account.id,
          operationKey,
          riskClass: input.riskClass,
          capabilityId: input.capabilityId,
          secretRouteId: input.secretRouteId,
          requestProfile: input.requestProfile ?? {},
          responseProfile: input.responseProfile ?? {},
        })
        .returning();
      if (input.secretRouteId) {
        const credentialSecretId = account.credentialSecretId;
        if (!credentialSecretId) {
          throw new ProviderAuthorityError(
            "provider account has no credential binding",
            "forbidden",
            403,
          );
        }
        const [boundRoute] = await tx
          .update(secretRoutes)
          .set({
            authorityMode: "governed_v2",
            providerOperationId: row.id,
            ...(genericDescriptor
              ? { pathPattern: genericDescriptorGovernedRoutePattern(genericDescriptor) }
              : {}),
          })
          .where(
            and(
              eq(secretRoutes.id, input.secretRouteId),
              eq(secretRoutes.tenantId, ctx.tenantId),
              eq(secretRoutes.secretId, credentialSecretId),
              eq(secretRoutes.authorityMode, "legacy"),
              sql`${secretRoutes.providerOperationId} IS NULL`,
            ),
          )
          .returning();
        if (!boundRoute) {
          throw new ProviderAuthorityError(
            "credential route changed during operation registration",
            "revision_conflict",
            409,
          );
        }
      }
      return row;
    });
  }

  async listOperations(tenantId: string, workspaceId: string | undefined, accountId: string) {
    if (!workspaceId) return [];
    return this.db()
      .select()
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, tenantId),
          eq(providerOperations.workspaceId, workspaceId),
          eq(providerOperations.providerAccountId, accountId),
        ),
      );
  }

  private async validatePrincipal(
    tenantId: string,
    type: ProviderPrincipalType,
    id: string,
  ): Promise<void> {
    if (type === "agent") {
      const [agent] = await this.db()
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.tenantId, tenantId), eq(agents.id, id)))
        .limit(1);
      if (!agent) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    } else {
      const membership = await this.membership(tenantId, id);
      if (!membership) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    }
  }

  async issueRoleBinding(
    ctx: MutationContext,
    input: Omit<
      BindingInsert,
      | "id"
      | "tenantId"
      | "status"
      | "revision"
      | "grantedByUserId"
      | "reason"
      | "createdAt"
      | "updatedAt"
    >,
  ) {
    assertMutationContext(ctx);
    if (
      !PRINCIPAL_TYPES.has(input.principalType) ||
      !ROLES.has(input.roleKey) ||
      (input.environment && !ENVIRONMENTS.has(input.environment))
    ) {
      throw new ProviderAuthorityError("invalid role binding vocabulary", "bad_request", 400);
    }
    if (
      (input.notBefore && !Number.isFinite(input.notBefore.getTime())) ||
      (input.expiresAt && !Number.isFinite(input.expiresAt.getTime())) ||
      (input.notBefore && input.expiresAt && input.expiresAt <= input.notBefore)
    ) {
      throw new ProviderAuthorityError("invalid role binding lifetime", "bad_request", 400);
    }
    await this.validatePrincipal(ctx.tenantId, input.principalType, input.principalId);
    const tenantRole = input.roleKey === "tenant_authority_admin";
    if (tenantRole) {
      if (!(await this.hasTenantAdmin(ctx)))
        throw new ProviderAuthorityError("tenant authority required", "forbidden", 403);
      const revision = await this.ensureTenantState(ctx.tenantId);
      if (revision !== ctx.expectedRevision)
        throw new ProviderAuthorityError("authority revision conflict", "revision_conflict", 409);
      if (
        input.principalType !== "human" ||
        input.workspaceId ||
        input.providerAccountId ||
        input.environment
      )
        throw new ProviderAuthorityError(
          "tenant authority admin must be a tenant-scoped human without an environment scope",
          "bad_request",
          400,
        );
      const id = randomUUID();
      await ctx.audit({
        action: "provider.role_binding.issue",
        resourceType: "provider_role_binding",
        resourceId: id,
        metadata: {
          roleKey: input.roleKey,
          principalId: input.principalId,
          expectedRevision: revision,
          reason: ctx.reason,
        },
      });
      return this.db().transaction(async (tx) => {
        const [cas] = await tx
          .update(providerAuthorityTenantState)
          .set({ revision: revision + 1, bootstrapCompleted: true, updatedAt: new Date() })
          .where(
            and(
              eq(providerAuthorityTenantState.tenantId, ctx.tenantId),
              eq(providerAuthorityTenantState.revision, revision),
            ),
          )
          .returning();
        if (!cas)
          throw new ProviderAuthorityError("authority revision conflict", "revision_conflict", 409);
        const [row] = await tx
          .insert(providerRoleBindings)
          .values({
            ...input,
            id,
            tenantId: ctx.tenantId,
            grantedByUserId: ctx.actorUserId,
            reason: ctx.reason,
          })
          .returning();
        return row;
      });
    }
    if (!input.workspaceId)
      throw new ProviderAuthorityError("workspaceId is required", "bad_request", 400);
    const mandate = await this.requireWorkspaceAdmin(ctx, input.workspaceId, true);
    if (input.roleKey === "workspace_admin" && mandate.type !== "tenant")
      throw new ProviderAuthorityError(
        "tenant authority required to assign workspace_admin",
        "forbidden",
        403,
      );
    if (input.providerAccountId) {
      const [account] = await this.db()
        .select()
        .from(providerAccounts)
        .where(
          and(
            eq(providerAccounts.tenantId, ctx.tenantId),
            eq(providerAccounts.workspaceId, input.workspaceId),
            eq(providerAccounts.id, input.providerAccountId),
          ),
        )
        .limit(1);
      if (!account) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    }
    const [workspace] = await this.db()
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, ctx.tenantId), eq(workspaces.id, input.workspaceId)))
      .limit(1);
    if (!workspace) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (workspace.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
    const requestedOperationKeys = input.operationKeys ?? [];
    if (
      (input.roleKey === "workspace_operator" || input.roleKey === "workspace_viewer") &&
      requestedOperationKeys.length === 0
    ) {
      throw new ProviderAuthorityError(
        "operationKeys are required for operator and viewer bindings",
        "bad_request",
        400,
      );
    }
    if (requestedOperationKeys.length > 0) {
      const scopedOperations = await this.db()
        .select({ key: providerOperations.operationKey, riskClass: providerOperations.riskClass })
        .from(providerOperations)
        .where(
          and(
            eq(providerOperations.tenantId, ctx.tenantId),
            eq(providerOperations.workspaceId, input.workspaceId),
            input.providerAccountId
              ? eq(providerOperations.providerAccountId, input.providerAccountId)
              : sql`true`,
            eq(providerOperations.status, "active"),
            inArray(providerOperations.operationKey, requestedOperationKeys),
          ),
        );
      if (scopedOperations.length !== new Set(requestedOperationKeys).size)
        throw new ProviderAuthorityError("operation set exceeds binding scope", "forbidden", 403);
      if (
        input.roleKey === "workspace_viewer" &&
        scopedOperations.some((operation) => operation.riskClass !== "read")
      )
        throw new ProviderAuthorityError(
          "workspace_viewer may include only read-class operations",
          "forbidden",
          403,
        );
    }
    if (mandate.operationKeys.length && !subset(requestedOperationKeys, mandate.operationKeys))
      throw new ProviderAuthorityError(
        "operation set exceeds administrator mandate",
        "forbidden",
        403,
      );
    const id = randomUUID();
    await ctx.audit({
      action: "provider.role_binding.issue",
      resourceType: "provider_role_binding",
      resourceId: id,
      metadata: {
        workspaceId: input.workspaceId,
        roleKey: input.roleKey,
        principalId: input.principalId,
        expectedRevision: workspace.revision,
        reason: ctx.reason,
      },
    });
    return this.db().transaction(async (tx) => {
      const [cas] = await tx
        .update(workspaces)
        .set({ revision: workspace.revision + 1, updatedAt: new Date() })
        .where(
          and(
            eq(workspaces.id, workspace.id),
            eq(workspaces.tenantId, ctx.tenantId),
            eq(workspaces.revision, workspace.revision),
          ),
        )
        .returning();
      if (!cas)
        throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
      const [row] = await tx
        .insert(providerRoleBindings)
        .values({
          ...input,
          id,
          tenantId: ctx.tenantId,
          grantedByUserId: ctx.actorUserId,
          reason: ctx.reason,
        })
        .returning();
      return row;
    });
  }

  async listRoleBindings(tenantId: string, workspaceId?: string) {
    if (!workspaceId)
      return this.db()
        .select()
        .from(providerRoleBindings)
        .where(
          and(
            eq(providerRoleBindings.tenantId, tenantId),
            sql`${providerRoleBindings.workspaceId} IS NULL`,
          ),
        );
    return this.db()
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.workspaceId, workspaceId),
        ),
      );
  }

  async revokeRoleBinding(ctx: MutationContext, id: string) {
    assertMutationContext(ctx);
    const [binding] = await this.db()
      .select()
      .from(providerRoleBindings)
      .where(and(eq(providerRoleBindings.id, id), eq(providerRoleBindings.tenantId, ctx.tenantId)))
      .limit(1);
    if (!binding) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (binding.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("binding revision conflict", "revision_conflict", 409);
    if (binding.roleKey === "tenant_authority_admin") {
      if (!(await this.hasTenantAdmin(ctx)))
        throw new ProviderAuthorityError("tenant authority required", "forbidden", 403);
      const admins = await this.activeTenantAdmins(ctx.tenantId);
      if (admins.length <= 1)
        throw new ProviderAuthorityError(
          "cannot revoke the last active tenant authority admin",
          "last_admin",
          409,
        );
    } else {
      if (!binding.workspaceId)
        throw new ProviderAuthorityError("resource not found", "not_found", 404);
      const isOriginalGrantor =
        binding.grantedByUserId === ctx.actorUserId &&
        Boolean(
          await this.workspaceAdminMandate(ctx.tenantId, binding.workspaceId, ctx.actorUserId),
        );
      if (!isOriginalGrantor) await this.requireWorkspaceAdmin(ctx, binding.workspaceId, true);
    }
    await ctx.audit({
      action: "provider.role_binding.revoke",
      resourceType: "provider_role_binding",
      resourceId: id,
      metadata: {
        workspaceId: binding.workspaceId,
        roleKey: binding.roleKey,
        expectedRevision: binding.revision,
        reason: ctx.reason,
      },
    });
    const [updated] = await this.db()
      .update(providerRoleBindings)
      .set({ status: "revoked", revision: binding.revision + 1, updatedAt: new Date() })
      .where(
        and(
          eq(providerRoleBindings.id, id),
          eq(providerRoleBindings.tenantId, ctx.tenantId),
          eq(providerRoleBindings.revision, binding.revision),
          eq(providerRoleBindings.status, "active"),
        ),
      )
      .returning();
    if (!updated)
      throw new ProviderAuthorityError("binding revision conflict", "revision_conflict", 409);
    return updated;
  }

  async issueGrant(
    ctx: MutationContext,
    input: Pick<
      GrantInsert,
      | "workspaceId"
      | "providerAccountId"
      | "agentId"
      | "operationKeys"
      | "environment"
      | "notBefore"
      | "expiresAt"
    >,
  ) {
    assertMutationContext(ctx);
    if (input.environment && !ENVIRONMENTS.has(input.environment))
      throw new ProviderAuthorityError("invalid environment", "bad_request", 400);
    if (input.notBefore && !Number.isFinite(input.notBefore.getTime()))
      throw new ProviderAuthorityError("invalid notBefore", "bad_request", 400);
    const mandate = await this.requireWorkspaceAdmin(ctx, input.workspaceId, true);
    await this.validatePrincipal(ctx.tenantId, "agent", input.agentId);
    const [workspace] = await this.db()
      .select()
      .from(workspaces)
      .where(
        and(
          eq(workspaces.tenantId, ctx.tenantId),
          eq(workspaces.id, input.workspaceId),
          eq(workspaces.status, "active"),
        ),
      )
      .limit(1);
    const [account] = await this.db()
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, ctx.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.id, input.providerAccountId),
          eq(providerAccounts.status, "active"),
        ),
      )
      .limit(1);
    if (!workspace || !account)
      throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (workspace.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
    const keys = [...new Set(input.operationKeys.map((key) => key.trim()).filter(Boolean))];
    if (!keys.length)
      throw new ProviderAuthorityError("operationKeys must not be empty", "bad_request", 400);
    const operations = await this.db()
      .select({ key: providerOperations.operationKey })
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, ctx.tenantId),
          eq(providerOperations.workspaceId, input.workspaceId),
          eq(providerOperations.providerAccountId, input.providerAccountId),
          eq(providerOperations.status, "active"),
          inArray(providerOperations.operationKey, keys),
        ),
      );
    if (operations.length !== keys.length)
      throw new ProviderAuthorityError(
        "operation set exceeds provider account operations",
        "forbidden",
        403,
      );
    if (mandate.operationKeys.length && !subset(keys, mandate.operationKeys))
      throw new ProviderAuthorityError(
        "operation set exceeds administrator mandate",
        "forbidden",
        403,
      );
    const expiresAt =
      input.expiresAt instanceof Date
        ? input.expiresAt
        : new Date(input.expiresAt as unknown as string);
    if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= new Date())
      throw new ProviderAuthorityError("expiresAt must be in the future", "bad_request", 400);
    if (input.notBefore && expiresAt <= input.notBefore)
      throw new ProviderAuthorityError("expiresAt must be after notBefore", "bad_request", 400);
    const id = randomUUID();
    await ctx.audit({
      action: "provider.grant.issue",
      resourceType: "provider_grant",
      resourceId: id,
      metadata: {
        workspaceId: input.workspaceId,
        providerAccountId: input.providerAccountId,
        agentId: input.agentId,
        operationKeys: keys,
        nonDelegable: true,
        expectedRevision: workspace.revision,
        reason: ctx.reason,
      },
    });
    return this.db().transaction(async (tx) => {
      const [cas] = await tx
        .update(workspaces)
        .set({ revision: workspace.revision + 1, updatedAt: new Date() })
        .where(
          and(
            eq(workspaces.id, workspace.id),
            eq(workspaces.tenantId, ctx.tenantId),
            eq(workspaces.revision, workspace.revision),
          ),
        )
        .returning();
      if (!cas)
        throw new ProviderAuthorityError("workspace revision conflict", "revision_conflict", 409);
      const [row] = await tx
        .insert(providerGrants)
        .values({
          ...input,
          id,
          tenantId: ctx.tenantId,
          operationKeys: keys,
          expiresAt,
          grantedByUserId: ctx.actorUserId,
          reason: ctx.reason,
        })
        .returning();
      return row;
    });
  }

  async listGrants(tenantId: string, workspaceId?: string) {
    if (!workspaceId) return [];
    return this.db()
      .select()
      .from(providerGrants)
      .where(
        and(eq(providerGrants.tenantId, tenantId), eq(providerGrants.workspaceId, workspaceId)),
      );
  }

  async revokeGrant(ctx: MutationContext, id: string) {
    assertMutationContext(ctx);
    const [grant] = await this.db()
      .select()
      .from(providerGrants)
      .where(and(eq(providerGrants.id, id), eq(providerGrants.tenantId, ctx.tenantId)))
      .limit(1);
    if (!grant) throw new ProviderAuthorityError("resource not found", "not_found", 404);
    if (grant.revision !== ctx.expectedRevision)
      throw new ProviderAuthorityError("grant revision conflict", "revision_conflict", 409);
    const originalGrantor =
      grant.grantedByUserId === ctx.actorUserId &&
      Boolean(await this.workspaceAdminMandate(ctx.tenantId, grant.workspaceId, ctx.actorUserId));
    if (!originalGrantor) await this.requireWorkspaceAdmin(ctx, grant.workspaceId, true);
    await ctx.audit({
      action: "provider.grant.revoke",
      resourceType: "provider_grant",
      resourceId: id,
      metadata: {
        workspaceId: grant.workspaceId,
        agentId: grant.agentId,
        expectedRevision: grant.revision,
        reason: ctx.reason,
      },
    });
    const [updated] = await this.db()
      .update(providerGrants)
      .set({
        status: "revoked",
        revision: grant.revision + 1,
        revokedAt: new Date(),
        revokedByUserId: ctx.actorUserId,
        revocationReason: ctx.reason,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerGrants.id, id),
          eq(providerGrants.tenantId, ctx.tenantId),
          eq(providerGrants.workspaceId, grant.workspaceId),
          eq(providerGrants.revision, grant.revision),
          eq(providerGrants.status, "active"),
        ),
      )
      .returning();
    if (!updated)
      throw new ProviderAuthorityError("grant revision conflict", "revision_conflict", 409);
    return updated;
  }

  /** Direct grants are terminal authority objects. There is intentionally no delegate method. */
  async checkAccess(request: ProviderAccessRequestV1): Promise<ProviderAccessDecisionV1> {
    const decisionId = randomUUID();
    const evaluatedAt = new Date(request.evaluatedAt);
    const decidedAt = new Date().toISOString();
    const deny = (
      reasonCode: string,
      revisions: ProviderAccessDecisionV1["dependencyRevisions"] = {
        actor: 0,
        workspace: 0,
        providerAccount: 0,
        operation: 0,
        bindings: [],
        grants: [],
      },
    ): ProviderAccessDecisionV1 => ({
      decisionId,
      effect: "deny",
      reasonCode,
      matchedBindingIds: [],
      matchedGrantIds: [],
      dependencyRevisions: revisions,
      decidedAt,
    });
    if (
      !Number.isFinite(evaluatedAt.getTime()) ||
      Math.abs(Date.now() - evaluatedAt.getTime()) > 5 * 60_000
    )
      return deny(PROVIDER_ACCESS_REASON.RESOURCE_NOT_FOUND);
    const actorActive =
      request.actor.type === "agent"
        ? Boolean(
            (
              await this.db()
                .select({ id: agents.id })
                .from(agents)
                .where(and(eq(agents.tenantId, request.tenantId), eq(agents.id, request.actor.id)))
                .limit(1)
            )[0],
          )
        : Boolean(await this.membership(request.tenantId, request.actor.id));
    if (!actorActive) return deny(PROVIDER_ACCESS_REASON.ACTOR_INACTIVE);
    const [workspace] = await this.db()
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, request.tenantId), eq(workspaces.id, request.workspaceId)))
      .limit(1);
    const [account] = await this.db()
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, request.tenantId),
          eq(providerAccounts.workspaceId, request.workspaceId),
          eq(providerAccounts.id, request.providerAccountId),
        ),
      )
      .limit(1);
    const [operation] = await this.db()
      .select()
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, request.tenantId),
          eq(providerOperations.workspaceId, request.workspaceId),
          eq(providerOperations.providerAccountId, request.providerAccountId),
          eq(providerOperations.operationKey, request.operationKey),
        ),
      )
      .limit(1);
    if (!workspace || !account || !operation)
      return deny(PROVIDER_ACCESS_REASON.RESOURCE_NOT_FOUND);
    const baseRevisions = {
      actor: 1,
      workspace: workspace.revision,
      providerAccount: account.revision,
      operation: operation.revision,
      bindings: [] as Array<{ id: string; revision: number }>,
      grants: [] as Array<{ id: string; revision: number }>,
    };
    if (
      workspace.status !== "active" ||
      account.status !== "active" ||
      operation.status !== "active" ||
      workspace.environment !== request.environment
    )
      return deny(PROVIDER_ACCESS_REASON.RESOURCE_INACTIVE, baseRevisions);
    const bindingRows = await this.db()
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, request.tenantId),
          eq(providerRoleBindings.workspaceId, request.workspaceId),
          eq(providerRoleBindings.principalType, request.actor.type),
          eq(providerRoleBindings.principalId, request.actor.id),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    const matchedBindings = bindingRows.filter((binding) => {
      if (!activeAt(binding, evaluatedAt, request.environment)) return false;
      if (binding.providerAccountId && binding.providerAccountId !== request.providerAccountId)
        return false;
      if (binding.roleKey === "workspace_operator")
        return operationIncluded(binding.operationKeys, request.operationKey);
      if (binding.roleKey === "workspace_viewer")
        return (
          operation.riskClass === "read" &&
          operationIncluded(binding.operationKeys, request.operationKey)
        );
      return false;
    });
    const grantRows =
      request.actor.type === "agent"
        ? await this.db()
            .select()
            .from(providerGrants)
            .where(
              and(
                eq(providerGrants.tenantId, request.tenantId),
                eq(providerGrants.workspaceId, request.workspaceId),
                eq(providerGrants.providerAccountId, request.providerAccountId),
                eq(providerGrants.agentId, request.actor.id),
                eq(providerGrants.status, "active"),
              ),
            )
        : [];
    const matchedGrants = grantRows.filter(
      (grant) =>
        activeAt(grant, evaluatedAt, request.environment) &&
        operationIncluded(grant.operationKeys, request.operationKey),
    );
    const revisions = {
      ...baseRevisions,
      bindings: matchedBindings.map(({ id, revision }) => ({ id, revision })),
      grants: matchedGrants.map(({ id, revision }) => ({ id, revision })),
    };
    if (!matchedBindings.length && !matchedGrants.length)
      return deny(PROVIDER_ACCESS_REASON.NO_MATCHING_AUTHORITY, revisions);
    return {
      decisionId,
      effect: "allow",
      reasonCode: PROVIDER_ACCESS_REASON.ALLOWED,
      matchedBindingIds: matchedBindings.map((row) => row.id),
      matchedGrantIds: matchedGrants.map((row) => row.id),
      dependencyRevisions: revisions,
      decidedAt,
    };
  }
}

export const providerAuthorityStore = new ProviderAuthorityStore();
