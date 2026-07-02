/**
 * store.ts — the capability plugin's transactional data layer.
 *
 * this owns the KEY architectural piece: the paired secret_route lifecycle. one
 * capability compiles to a legal narrow secret_route (the proxy's injection
 * mechanism); a GRANT (agent X may use capability Y) materializes that route for
 * that agent. every mutation that could leave a live injection path is done in a
 * single DB transaction so there is never an orphaned ENABLED route:
 *
 *   - grant create      -> insert grant + insert its paired enabled secret_route (tx)
 *   - grant revoke       -> mark grant revoked + delete its paired route (tx)
 *   - capability disable -> disable capability + disable every grant's paired route (tx)
 *   - capability enable  -> enable capability + re-enable every ACTIVE, unexpired
 *                           grant's paired route (tx); revoked/expired stay off
 *   - capability delete  -> delete every paired route + grants + the capability (tx)
 *   - capability update  -> update capability + rewrite every paired route's
 *                           match/inject fields (tx)
 *
 * WHY PER-GRANT (not per-capability): the proxy's route matcher selects
 * secret_routes by EXACT (tenantId, agentId) equality (packages/proxy +
 * packages/vault route-matcher). capabilities are tenant-wide (UNIQUE(tenant,
 * name)) with per-agent grants, so a single tenant-wide route could not be
 * matched for a specific agent without changing the proxy's matching semantics.
 * materializing one route per grant (agentId = the grant's agent) keeps the
 * proxy UNCHANGED. documented in the PR body as the locked design call.
 *
 * the plugin NEVER decrypts a secret and NEVER injects a credential itself — it
 * only maintains the secret_route ROWS the already-defended proxy consumes. the
 * injection config lives on the capability so a capability compiles to exactly
 * one legal route; every field is validated by the SHARED secret-route validator
 * before any row is written.
 */

import { agents, and, eq, type NewSecretRoute, type SecretRoute, secretRoutes } from "@stwd/db";
import {
  type Capability,
  capabilities,
  type CapabilityGrant,
  capabilityGrants,
} from "./schema";

/**
 * a drizzle db handle (the core hands it via ctx.db). typed loosely so the plugin
 * does not couple to a specific driver — the core injects a real postgres-js /
 * pglite handle. the members used here (select/insert/update/delete/transaction)
 * are common to every drizzle driver.
 */
// biome-ignore lint/suspicious/noExplicitAny: drizzle's db handle is driver-typed
// (postgres-js/pglite/neon); the store accepts any drizzle db exposing the common
// query builder + transaction. the core injects the concrete handle.
export type Db = any;

/** fields that define a capability's target + injection (validated together). */
export interface CapabilitySpec {
  secretId: string;
  host: string;
  pathPattern: string;
  method: string;
  injectAs: string;
  injectKey: string;
  injectFormat: string;
}

type CapabilityRouteFields = Pick<
  Capability,
  "secretId" | "host" | "pathPattern" | "method" | "injectAs" | "injectKey" | "injectFormat"
>;

/** map a capability's routing/injection fields onto a secret_route insert. */
function routeValuesFor(
  tenantId: string,
  agentId: string,
  cap: CapabilityRouteFields,
  enabled: boolean,
): NewSecretRoute {
  return {
    tenantId,
    agentId,
    secretId: cap.secretId,
    hostPattern: cap.host,
    pathPattern: cap.pathPattern,
    method: cap.method,
    injectAs: cap.injectAs,
    injectKey: cap.injectKey,
    injectFormat: cap.injectFormat,
    // capabilities are pinned to an exact endpoint, so default 0 is fine (the
    // matcher's specificity ordering handles precedence).
    priority: 0,
    enabled,
  };
}

export class CapabilityStore {
  constructor(private readonly db: Db) {}

  // ── capability reads ────────────────────────────────────────────────────────

  async getCapabilityById(tenantId: string, id: string): Promise<Capability | null> {
    const [row] = await this.db
      .select()
      .from(capabilities)
      .where(and(eq(capabilities.id, id), eq(capabilities.tenantId, tenantId)));
    return row ?? null;
  }

  async getCapabilityByName(tenantId: string, name: string): Promise<Capability | null> {
    const [row] = await this.db
      .select()
      .from(capabilities)
      .where(and(eq(capabilities.name, name), eq(capabilities.tenantId, tenantId)));
    return row ?? null;
  }

  async listCapabilities(tenantId: string): Promise<Capability[]> {
    return this.db.select().from(capabilities).where(eq(capabilities.tenantId, tenantId));
  }

  // ── capability create ─────────────────────────────────────────────────────

  /**
   * Create a capability. No grants yet, so NO paired routes are materialized (a
   * capability with zero grants attaches the credential to nothing — fail-closed
   * by construction). The caller MUST have validated the spec through the shared
   * secret-route validator first.
   */
  async createCapability(input: {
    tenantId: string;
    name: string;
    spec: CapabilitySpec;
    constraints: Record<string, unknown>;
    enabled: boolean;
  }): Promise<Capability> {
    const [row] = await this.db
      .insert(capabilities)
      .values({
        tenantId: input.tenantId,
        name: input.name,
        secretId: input.spec.secretId,
        host: input.spec.host,
        pathPattern: input.spec.pathPattern,
        method: input.spec.method,
        injectAs: input.spec.injectAs,
        injectKey: input.spec.injectKey,
        injectFormat: input.spec.injectFormat,
        constraints: input.constraints,
        enabled: input.enabled,
      })
      .returning();
    return row;
  }

  // ── capability update (enable/disable + routing/inject/constraints) ─────────

  /**
   * Update a capability transactionally, rewriting every paired route so the
   * proxy's injection stays exactly in sync with the capability.
   *
   * - `enabled` -> false: capability + every paired route disabled.
   * - `enabled` -> true: capability enabled + every ACTIVE, unexpired grant's
   *   route re-enabled (revoked/expired grants keep their route disabled).
   * - routing/inject fields changed: capability updated + every paired route's
   *   match/inject fields rewritten (a narrowing update narrows the live route
   *   too — no widen-by-patch escaping the proxy).
   *
   * `now` is injected for deterministic expiry evaluation in tests.
   */
  async updateCapability(
    tenantId: string,
    id: string,
    patch: {
      spec?: CapabilitySpec;
      constraints?: Record<string, unknown>;
      enabled?: boolean;
    },
    now: Date = new Date(),
  ): Promise<Capability | null> {
    return this.db.transaction(async (tx: Db) => {
      const [current] = await tx
        .select()
        .from(capabilities)
        .where(and(eq(capabilities.id, id), eq(capabilities.tenantId, tenantId)));
      if (!current) return null;

      const set: Record<string, unknown> = { updatedAt: now };
      if (patch.spec) {
        set.secretId = patch.spec.secretId;
        set.host = patch.spec.host;
        set.pathPattern = patch.spec.pathPattern;
        set.method = patch.spec.method;
        set.injectAs = patch.spec.injectAs;
        set.injectKey = patch.spec.injectKey;
        set.injectFormat = patch.spec.injectFormat;
      }
      if (patch.constraints !== undefined) set.constraints = patch.constraints;
      if (patch.enabled !== undefined) set.enabled = patch.enabled;

      const [updated] = await tx
        .update(capabilities)
        .set(set)
        .where(and(eq(capabilities.id, id), eq(capabilities.tenantId, tenantId)))
        .returning();

      // the capability's routing/inject fields as they are AFTER this patch.
      const merged: CapabilityRouteFields = patch.spec ? { ...patch.spec } : current;
      const willBeEnabled = patch.enabled ?? current.enabled;

      const grants: CapabilityGrant[] = await tx
        .select()
        .from(capabilityGrants)
        .where(
          and(eq(capabilityGrants.tenantId, tenantId), eq(capabilityGrants.capabilityId, id)),
        );

      for (const grant of grants) {
        if (!grant.secretRouteId) continue;
        // a route stays enabled only if the capability is enabled AND the grant
        // is active + unexpired. otherwise it is disabled (fail-closed).
        const grantUsable = grant.status === "active" && !isExpired(grant.expiresAt, now);
        const routeEnabled = willBeEnabled && grantUsable;
        await tx
          .update(secretRoutes)
          .set({
            secretId: merged.secretId,
            hostPattern: merged.host,
            pathPattern: merged.pathPattern,
            method: merged.method,
            injectAs: merged.injectAs,
            injectKey: merged.injectKey,
            injectFormat: merged.injectFormat,
            enabled: routeEnabled,
          })
          .where(
            and(eq(secretRoutes.id, grant.secretRouteId), eq(secretRoutes.tenantId, tenantId)),
          );
      }

      return updated;
    });
  }

  // ── capability delete ────────────────────────────────────────────────────

  /**
   * Delete a capability transactionally: remove every paired secret_route, then
   * every grant, then the capability. No route can survive the delete.
   */
  async deleteCapability(tenantId: string, id: string): Promise<boolean> {
    return this.db.transaction(async (tx: Db) => {
      const [current] = await tx
        .select()
        .from(capabilities)
        .where(and(eq(capabilities.id, id), eq(capabilities.tenantId, tenantId)));
      if (!current) return false;

      const grants: CapabilityGrant[] = await tx
        .select()
        .from(capabilityGrants)
        .where(
          and(eq(capabilityGrants.tenantId, tenantId), eq(capabilityGrants.capabilityId, id)),
        );

      for (const grant of grants) {
        if (grant.secretRouteId) {
          await tx
            .delete(secretRoutes)
            .where(
              and(eq(secretRoutes.id, grant.secretRouteId), eq(secretRoutes.tenantId, tenantId)),
            );
        }
      }

      // grants would cascade on capability delete (FK ON DELETE CASCADE), but
      // delete them explicitly first so behavior does not depend on the driver's
      // FK cascade support.
      await tx
        .delete(capabilityGrants)
        .where(
          and(eq(capabilityGrants.tenantId, tenantId), eq(capabilityGrants.capabilityId, id)),
        );
      await tx
        .delete(capabilities)
        .where(and(eq(capabilities.id, id), eq(capabilities.tenantId, tenantId)));
      return true;
    });
  }

  // ── grant reads ────────────────────────────────────────────────────────────

  async getGrantById(tenantId: string, grantId: string): Promise<CapabilityGrant | null> {
    const [row] = await this.db
      .select()
      .from(capabilityGrants)
      .where(and(eq(capabilityGrants.id, grantId), eq(capabilityGrants.tenantId, tenantId)));
    return row ?? null;
  }

  async listGrantsForCapability(
    tenantId: string,
    capabilityId: string,
  ): Promise<CapabilityGrant[]> {
    return this.db
      .select()
      .from(capabilityGrants)
      .where(
        and(
          eq(capabilityGrants.tenantId, tenantId),
          eq(capabilityGrants.capabilityId, capabilityId),
        ),
      );
  }

  /**
   * The capabilities an agent may USE right now: an ACTIVE, unexpired grant to an
   * ENABLED capability. This is what the W-1c invoke path will consult. Expired
   * or revoked grants, and disabled capabilities, are excluded (fail-closed).
   */
  async listUsableCapabilitiesForAgent(
    tenantId: string,
    agentId: string,
    now: Date = new Date(),
  ): Promise<Array<{ capability: Capability; grant: CapabilityGrant }>> {
    const rows: Array<{ capability: Capability; grant: CapabilityGrant }> = await this.db
      .select({ capability: capabilities, grant: capabilityGrants })
      .from(capabilityGrants)
      .innerJoin(capabilities, eq(capabilityGrants.capabilityId, capabilities.id))
      .where(
        and(
          eq(capabilityGrants.tenantId, tenantId),
          eq(capabilityGrants.agentId, agentId),
          eq(capabilityGrants.status, "active"),
          eq(capabilities.enabled, true),
        ),
      );
    return rows.filter((r) => !isExpired(r.grant.expiresAt, now));
  }

  // ── grant create (materializes the paired route) ────────────────────────────

  /**
   * Grant `agentId` the use of a capability, materializing the paired
   * secret_route transactionally. The route is enabled iff the capability is
   * enabled and the grant is unexpired at creation. Verifies the agent belongs
   * to the tenant (fail-closed: unknown agent = throw, no grant, no route).
   */
  async createGrant(input: {
    tenantId: string;
    capabilityId: string;
    agentId: string;
    expiresAt: Date | null;
    now?: Date;
  }): Promise<{ grant: CapabilityGrant; route: SecretRoute | null } | null> {
    const now = input.now ?? new Date();
    return this.db.transaction(async (tx: Db) => {
      const [cap] = await tx
        .select()
        .from(capabilities)
        .where(
          and(
            eq(capabilities.id, input.capabilityId),
            eq(capabilities.tenantId, input.tenantId),
          ),
        );
      if (!cap) return null;

      // agent must exist under this tenant (mirrors SecretVault.createRoute's
      // fail-closed agent check, so a grant never points a route at a phantom agent).
      const [agent] = await tx
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.id, input.agentId), eq(agents.tenantId, input.tenantId)));
      if (!agent) throw new AgentNotFoundError(input.agentId, input.tenantId);

      // reject a duplicate grant PROACTIVELY (before materializing a route), so
      // the unique(tenant, agent, capability) constraint is surfaced as a typed
      // error rather than a driver-wrapped 500 — and no orphaned route is created
      // (the insert is never attempted). fail-closed.
      const [existing] = await tx
        .select({ id: capabilityGrants.id })
        .from(capabilityGrants)
        .where(
          and(
            eq(capabilityGrants.tenantId, input.tenantId),
            eq(capabilityGrants.agentId, input.agentId),
            eq(capabilityGrants.capabilityId, input.capabilityId),
          ),
        );
      if (existing) throw new GrantExistsError(input.agentId, input.capabilityId);

      const unexpired = !isExpired(input.expiresAt, now);
      const routeEnabled = cap.enabled && unexpired;

      const [route] = await tx
        .insert(secretRoutes)
        .values(routeValuesFor(input.tenantId, input.agentId, cap, routeEnabled))
        .returning();

      const [grant] = await tx
        .insert(capabilityGrants)
        .values({
          tenantId: input.tenantId,
          agentId: input.agentId,
          capabilityId: input.capabilityId,
          secretRouteId: route.id,
          expiresAt: input.expiresAt,
          status: "active",
        })
        .returning();

      return { grant, route };
    });
  }

  // ── grant revoke (tears down the paired route) ──────────────────────────────

  /**
   * Revoke a grant transactionally: mark it revoked and DELETE its paired route
   * so the credential can no longer be injected for that agent. Idempotent on an
   * already-revoked grant (route already gone). Returns false if the grant does
   * not exist for the tenant.
   */
  async revokeGrant(tenantId: string, grantId: string): Promise<boolean> {
    return this.db.transaction(async (tx: Db) => {
      const [grant] = await tx
        .select()
        .from(capabilityGrants)
        .where(and(eq(capabilityGrants.id, grantId), eq(capabilityGrants.tenantId, tenantId)));
      if (!grant) return false;

      if (grant.secretRouteId) {
        await tx
          .delete(secretRoutes)
          .where(
            and(eq(secretRoutes.id, grant.secretRouteId), eq(secretRoutes.tenantId, tenantId)),
          );
      }
      await tx
        .update(capabilityGrants)
        .set({ status: "revoked", secretRouteId: null })
        .where(and(eq(capabilityGrants.id, grantId), eq(capabilityGrants.tenantId, tenantId)));
      return true;
    });
  }
}

/**
 * Thrown when a grant targets an agent that does not exist under the tenant. The
 * route layer maps this to a 404 (fail-closed: no grant, no route).
 */
export class AgentNotFoundError extends Error {
  constructor(agentId: string, tenantId: string) {
    super(`Agent ${agentId} not found for tenant ${tenantId}`);
    this.name = "AgentNotFoundError";
  }
}

/**
 * Thrown when an agent is already granted a capability (the
 * unique(tenant, agent, capability) invariant). The route layer maps this to a
 * 409. Detected proactively so no orphaned route is created.
 */
export class GrantExistsError extends Error {
  constructor(agentId: string, capabilityId: string) {
    super(`Agent ${agentId} is already granted capability ${capabilityId}`);
    this.name = "GrantExistsError";
  }
}

/** true if `expiresAt` is set and at/before `now` (expired). null = never. */
export function isExpired(expiresAt: Date | string | null, now: Date): boolean {
  if (!expiresAt) return false;
  const t = expiresAt instanceof Date ? expiresAt.getTime() : Date.parse(expiresAt);
  if (!Number.isFinite(t)) return false;
  return t <= now.getTime();
}
