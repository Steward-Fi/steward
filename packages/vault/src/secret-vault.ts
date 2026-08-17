/**
 * Secret Vault — encrypted credential storage for tenant API keys and secrets.
 *
 * Reuses the KeyStore's AES-256-GCM encryption. Secrets are encrypted per-tenant
 * using the same master key hierarchy as wallet keys.
 *
 * NO READ-BACK is a property of THIS plane (sovereign-custody Pillar A / A2):
 *
 *   - No HTTP route returns a plaintext secret value. The /secrets routes
 *     return {@link SecretMetadata} only (enforced by the static route scan in
 *     packages/api/src/__tests__/secrets-no-read-back.test.ts).
 *   - In-process, the canonical use-only path is {@link SecretVault.exerciseSecret}:
 *     decrypt → hand to a caller closure → drop the reference. The closure
 *     returns a RESULT (an HTTP response, a signature), never the secret.
 *   - The remaining direct decrypt callers ({@link decryptSecret} /
 *     {@link decryptSecretRow}) form a CLOSED, CI-pinned set (proxy credential
 *     injection + provider-x refresh). Adding a new caller fails the
 *     no-read-back inventory test with a classification instruction.
 *
 * Custody strength is orthogonal and inherited: the master-password root can be
 * wrapped by KMS-envelope (aws|pkcs11) via vault-factory custody modes, and the
 * TEE path (Pillar B) swaps the master-key source for an attestation-gated
 * release WITHOUT changing this API. There is deliberately NO parallel
 * file-based secret store — one custody plane, one audit surface.
 */

import {
  agents,
  and,
  desc,
  eq,
  getDb,
  inArray,
  isNull,
  type Secret,
  type SecretRoute,
  secretRoutes,
  secrets,
} from "@stwd/db";
import { type EncryptedKey, KeyStore } from "./keystore";
import {
  assertGovernedRouteUpdateIsSafe,
  assertNoOppositeAuthorityOverlap,
  lockSecretRouteNamespaces,
  SecretRouteAuthorityConflict,
} from "./secret-route-authority";
import { validateSecretRouteConfig } from "./secret-route-validator";

export interface SecretMetadata {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  version: number;
  rotatedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateSecretOptions {
  description?: string;
  expiresAt?: Date;
}

/**
 * A drizzle executor (the top-level db OR an open transaction) accepted by the
 * *WithinTx helpers so a caller can rotate a secret inside its OWN transaction
 * without a nested `db.transaction` (which deadlocks single-connection PGLite).
 */
export type SecretTxExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];
type DbBase = ReturnType<typeof getDb>;

export class SecretVault {
  private keyStore: KeyStore;
  // Legacy root (no domain label) — secrets encrypted before domain separation
  // shared the signing-vault's root. Kept only for decrypt fallback so existing
  // ciphertext stays readable; new secrets are always written under the
  // domain-separated `secret-vault` root above.
  private legacyKeyStore: KeyStore;

  constructor(masterPassword: string) {
    // Domain-separate the secret-vault root from the wallet signing-vault root so
    // compromising one path does not compromise the other (they share masterPassword).
    this.keyStore = new KeyStore(masterPassword, undefined, "secret-vault");
    this.legacyKeyStore = new KeyStore(masterPassword);
  }

  /**
   * Encrypt a secret value and store it in the database.
   */
  async createSecret(
    tenantId: string,
    name: string,
    value: string,
    options?: CreateSecretOptions,
  ): Promise<SecretMetadata> {
    const db = getDb();
    const encrypted = this.keyStore.encrypt(value, { tenantId, name, version: 1 });

    const [row] = await db
      .insert(secrets)
      .values({
        tenantId,
        name,
        description: options?.description ?? null,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.tag,
        salt: encrypted.salt,
        version: 1,
        expiresAt: options?.expiresAt ?? null,
      })
      .returning();

    return this.toMetadata(row);
  }

  /**
   * Get secret metadata by name (latest non-deleted version). Never returns decrypted value.
   */
  async getSecret(tenantId: string, name: string): Promise<SecretMetadata | null> {
    const db = getDb();
    const [row] = await db
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, name), isNull(secrets.deletedAt)))
      .orderBy(desc(secrets.version))
      .limit(1);

    return row ? this.toMetadata(row) : null;
  }

  /**
   * Get secret metadata by ID. Never returns decrypted value.
   */
  async getSecretById(tenantId: string, secretId: string): Promise<SecretMetadata | null> {
    const db = getDb();
    const [row] = await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.id, secretId), eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)),
      );

    return row ? this.toMetadata(row) : null;
  }

  /**
   * Exercise a secret: decrypt it and hand the plaintext to `use`, returning
   * the closure's RESULT. The plaintext is returned by NO public API path; it
   * exists for the duration of the `use` callback and the reference is dropped
   * afterwards. This is the canonical use-only consumption path for new
   * consumers (broker a call, sign a webhook, inject a header).
   *
   * Fail-closed audit: pass `beforeUse` as the audit chokepoint. It runs after
   * the secret row is located but BEFORE decryption; if it throws (e.g. the
   * audit append failed), the secret is never decrypted and `use` never runs.
   */
  async exerciseSecret<T>(
    tenantId: string,
    secretId: string,
    use: (plaintext: string) => T | Promise<T>,
    options?: { beforeUse?: () => void | Promise<void> },
  ): Promise<T> {
    const db = getDb();
    const [row] = await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.id, secretId), eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)),
      );
    if (!row) {
      throw new Error(`Secret ${secretId} not found for tenant ${tenantId}`);
    }
    return await this.exerciseSecretRow(tenantId, row, use, options);
  }

  /**
   * Exercise a secret row already read from the DB. This is the same use-only
   * plaintext lifetime as exerciseSecret, but supports intentional historical
   * row consumers such as KMS decrypt-old-version after rotation.
   */
  async exerciseSecretRow<T>(
    tenantId: string,
    row: Secret,
    use: (plaintext: string) => T | Promise<T>,
    options?: { beforeUse?: () => void | Promise<void> },
  ): Promise<T> {
    // Fail-closed: audit (or any precondition) must succeed before decryption.
    if (options?.beforeUse) await options.beforeUse();
    let plaintext: string | undefined = this.decryptSecretRow(tenantId, row);
    try {
      return await use(plaintext);
    } finally {
      // Best-effort drop of the reference. JS strings are immutable so the
      // bytes cannot be zeroed, but no live reference survives this method.
      plaintext = undefined;
      void plaintext;
    }
  }

  /**
   * Decrypt a secret for internal use (credential injection). NEVER expose via
   * API. Prefer {@link exerciseSecret} for new consumers — this direct-return
   * form exists for the proxy injection path, whose plaintext lifetime spans
   * the outbound request build, and its caller set is pinned by the
   * no-read-back inventory test.
   */
  async decryptSecret(tenantId: string, secretId: string): Promise<string> {
    const db = getDb();
    const [row] = await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.id, secretId), eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)),
      );

    if (!row) {
      throw new Error(`Secret ${secretId} not found for tenant ${tenantId}`);
    }
    return this.decryptSecretRow(tenantId, row);
  }

  /**
   * Decrypt a secret row already read from the DB (e.g. inside a caller's
   * transaction, so no fresh `getDb()` read is issued that would block on a
   * single-connection PGLite while an outer transaction holds the connection).
   * NEVER expose the plaintext via API.
   */
  decryptSecretRow(tenantId: string, row: Secret): string {
    if (row.expiresAt && row.expiresAt < new Date()) {
      throw new Error(`Secret ${row.id} has expired`);
    }
    const encrypted: EncryptedKey = {
      ciphertext: row.ciphertext,
      iv: row.iv,
      tag: row.authTag,
      salt: row.salt,
    };
    const context = { tenantId, name: row.name, version: row.version };
    try {
      return this.keyStore.decrypt(encrypted, context);
    } catch {
      // Backward compat: secrets written before domain separation are under the
      // legacy (shared) root. New secrets always use the domain-separated root above.
      return this.legacyKeyStore.decrypt(encrypted, context);
    }
  }

  /**
   * Rotate a secret WITHIN a caller-provided transaction. Identical to
   * {@link rotateSecret} but reuses the caller's `tx` instead of opening its own
   * `db.transaction`, so it can run inside an outer transaction (e.g. a per-
   * account refresh that holds a SELECT ... FOR UPDATE lock) without a nested
   * transaction. The single-flight/atomicity guarantee is the CALLER's outer
   * transaction; this method only appends the new version + repoints routes +
   * soft-deletes the prior version.
   */
  async rotateSecretWithinTx(
    tx: SecretTxExecutor,
    tenantId: string,
    name: string,
    newValue: string,
  ): Promise<SecretMetadata> {
    const [current] = await tx
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, name), isNull(secrets.deletedAt)))
      .orderBy(desc(secrets.version))
      .limit(1);
    if (!current) {
      throw new Error(`Secret "${name}" not found for tenant ${tenantId}`);
    }
    const newVersion = current.version + 1;
    const encrypted = this.keyStore.encrypt(newValue, { tenantId, name, version: newVersion });
    const now = new Date();

    const [row] = await tx
      .insert(secrets)
      .values({
        tenantId,
        name,
        description: current.description,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.tag,
        salt: encrypted.salt,
        version: newVersion,
        rotatedAt: now,
        expiresAt: current.expiresAt,
      })
      .returning();

    await tx
      .update(secretRoutes)
      .set({ secretId: row.id })
      .where(and(eq(secretRoutes.tenantId, tenantId), eq(secretRoutes.secretId, current.id)));

    await tx
      .update(secrets)
      .set({ deletedAt: now, updatedAt: now })
      .where(and(eq(secrets.id, current.id), eq(secrets.tenantId, tenantId)));

    return this.toMetadata(row);
  }

  /**
   * Rotate a secret — creates a new version with updated ciphertext.
   */
  async rotateSecret(tenantId: string, name: string, newValue: string): Promise<SecretMetadata> {
    const db = getDb();

    // Find current version
    const current = await this.getSecret(tenantId, name);
    if (!current) {
      throw new Error(`Secret "${name}" not found for tenant ${tenantId}`);
    }

    const newVersion = current.version + 1;
    const encrypted = this.keyStore.encrypt(newValue, { tenantId, name, version: newVersion });
    const now = new Date();

    return db.transaction(async (tx) => {
      const [row] = await tx
        .insert(secrets)
        .values({
          tenantId,
          name,
          description: current.description,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          authTag: encrypted.tag,
          salt: encrypted.salt,
          version: newVersion,
          rotatedAt: now,
          expiresAt: current.expiresAt,
        })
        .returning();

      await tx
        .update(secretRoutes)
        .set({ secretId: row.id })
        .where(and(eq(secretRoutes.tenantId, tenantId), eq(secretRoutes.secretId, current.id)));

      await tx
        .update(secrets)
        .set({ deletedAt: now, updatedAt: now })
        .where(and(eq(secrets.id, current.id), eq(secrets.tenantId, tenantId)));

      return this.toMetadata(row);
    });
  }

  /**
   * Soft-delete a secret (all versions).
   */
  async deleteSecret(tenantId: string, secretId: string): Promise<boolean> {
    const db = getDb();

    const [row] = await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.id, secretId), eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)),
      );

    if (!row) return false;

    const relatedSecretRows = await db
      .select({ id: secrets.id })
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, row.name)));

    const relatedSecretIds = relatedSecretRows.map((secretRow) => secretRow.id);
    const now = new Date();

    await db.transaction(async (tx) => {
      if (relatedSecretIds.length > 0) {
        await tx
          .delete(secretRoutes)
          .where(
            and(
              eq(secretRoutes.tenantId, tenantId),
              inArray(secretRoutes.secretId, relatedSecretIds),
            ),
          );
      }

      await tx
        .update(secrets)
        .set({ deletedAt: now, updatedAt: now })
        .where(
          and(
            eq(secrets.tenantId, tenantId),
            eq(secrets.name, row.name),
            isNull(secrets.deletedAt),
          ),
        );
    });

    return true;
  }

  /**
   * List all active secrets for a tenant (metadata only).
   */
  async listSecrets(tenantId: string): Promise<SecretMetadata[]> {
    const db = getDb();
    const rows = await db
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)))
      .orderBy(secrets.name, desc(secrets.version));

    // Deduplicate by name — only return latest version
    const seen = new Set<string>();
    const result: SecretMetadata[] = [];
    for (const row of rows) {
      if (!seen.has(row.name)) {
        seen.add(row.name);
        result.push(this.toMetadata(row));
      }
    }
    return result;
  }

  // ─── Route management ────────────────────────────────────────────────────────

  async createRoute(
    tenantId: string,
    secretId: string,
    config: {
      agentId: string;
      hostPattern: string;
      pathPattern?: string;
      method?: string;
      injectAs: string;
      injectKey: string;
      injectFormat?: string;
      priority?: number;
      enabled?: boolean;
      requiresApproval?: boolean;
      approvalConfig?: Record<string, unknown>;
    },
  ): Promise<SecretRoute> {
    return getDb().transaction((tx) => this.createRouteWithinTx(tx, tenantId, secretId, config));
  }

  /** Create a route inside a caller-owned transaction. */
  async createRouteWithinTx(
    db: SecretTxExecutor,
    tenantId: string,
    secretId: string,
    config: {
      agentId: string;
      hostPattern: string;
      pathPattern?: string;
      method?: string;
      injectAs: string;
      injectKey: string;
      injectFormat?: string;
      priority?: number;
      enabled?: boolean;
      requiresApproval?: boolean;
      approvalConfig?: Record<string, unknown>;
    },
  ): Promise<SecretRoute> {
    const normalizedConfig = {
      ...config,
      hostPattern: config.hostPattern.trim().toLowerCase(),
      pathPattern: config.pathPattern ?? "/",
      method: config.method?.trim().toUpperCase() ?? "GET",
      injectKey: config.injectKey.trim(),
      injectFormat: config.injectFormat ?? "{value}",
      priority: config.priority ?? 0,
    };
    const validationError = validateSecretRouteConfig(normalizedConfig);
    if (validationError) throw new Error(validationError);

    // Verify secret exists and belongs to tenant
    const [secret] = await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.id, secretId), eq(secrets.tenantId, tenantId), isNull(secrets.deletedAt)),
      )
      .limit(1);
    if (!secret) {
      throw new Error(`Secret ${secretId} not found for tenant ${tenantId}`);
    }
    if (secret.expiresAt && secret.expiresAt < new Date()) {
      throw new Error(`Secret ${secretId} has expired`);
    }

    const [agent] = await db
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, normalizedConfig.agentId), eq(agents.tenantId, tenantId)));
    if (!agent) {
      throw new Error(`Agent ${normalizedConfig.agentId} not found for tenant ${tenantId}`);
    }

    // Preserve the precise validation contract above, then take the durable
    // namespace lock immediately before mutation. If the agent disappears in
    // the validation/lock gap, the lock helper still fails closed.
    await lockSecretRouteNamespaces(db as never, tenantId, [normalizedConfig.agentId]);

    const [row] = await db
      .insert(secretRoutes)
      .values({
        tenantId,
        agentId: normalizedConfig.agentId,
        secretId,
        hostPattern: normalizedConfig.hostPattern,
        pathPattern: normalizedConfig.pathPattern,
        method: normalizedConfig.method,
        injectAs: normalizedConfig.injectAs,
        injectKey: normalizedConfig.injectKey,
        injectFormat: normalizedConfig.injectFormat,
        priority: normalizedConfig.priority,
        enabled: config.enabled ?? true,
        requiresApproval: config.requiresApproval ?? false,
        approvalConfig: config.approvalConfig ?? {},
      })
      .returning();

    await assertNoOppositeAuthorityOverlap(db as never, {
      ...row,
      agentId: config.agentId,
    });

    return row;
  }

  async listRoutes(tenantId: string): Promise<SecretRoute[]> {
    const db = getDb();
    return db
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.tenantId, tenantId))
      .orderBy(desc(secretRoutes.priority));
  }

  async getRoute(tenantId: string, routeId: string): Promise<SecretRoute | null> {
    const db = getDb();
    const [row] = await db
      .select()
      .from(secretRoutes)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)));
    return row ?? null;
  }

  async updateRoute(
    tenantId: string,
    routeId: string,
    updates: Partial<{
      hostPattern: string;
      agentId: string;
      pathPattern: string;
      method: string;
      injectAs: string;
      injectKey: string;
      injectFormat: string;
      priority: number;
      enabled: boolean;
      requiresApproval: boolean;
      approvalConfig: Record<string, unknown>;
    }>,
  ): Promise<SecretRoute | null> {
    return getDb().transaction((tx) => this.updateRouteWithinTx(tx, tenantId, routeId, updates));
  }

  /** Update a route inside a caller-owned transaction. */
  async updateRouteWithinTx(
    db: SecretTxExecutor,
    tenantId: string,
    routeId: string,
    updates: Partial<{
      hostPattern: string;
      agentId: string;
      pathPattern: string;
      method: string;
      injectAs: string;
      injectKey: string;
      injectFormat: string;
      priority: number;
      enabled: boolean;
      requiresApproval: boolean;
      approvalConfig: Record<string, unknown>;
    }>,
  ): Promise<SecretRoute | null> {
    const allowedUpdates: typeof updates = {};
    for (const key of [
      "hostPattern",
      "agentId",
      "pathPattern",
      "method",
      "injectAs",
      "injectKey",
      "injectFormat",
      "priority",
      "enabled",
      "requiresApproval",
      "approvalConfig",
    ] as const) {
      if (updates[key] !== undefined) allowedUpdates[key] = updates[key] as never;
    }
    if (Object.keys(allowedUpdates).length === 0) {
      const [unchanged] = await db
        .select()
        .from(secretRoutes)
        .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
        .limit(1);
      return unchanged ?? null;
    }
    const [beforeLock] = await db
      .select()
      .from(secretRoutes)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
      .limit(1);
    if (!beforeLock) return null;
    if (!beforeLock.agentId) {
      throw new SecretRouteAuthorityConflict("route has no agent namespace");
    }
    const destinationAgentId = allowedUpdates.agentId ?? beforeLock.agentId;
    await lockSecretRouteNamespaces(db as never, tenantId, [
      beforeLock.agentId,
      destinationAgentId,
    ]);
    const [lockedCurrent] = await db
      .select()
      .from(secretRoutes)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
      .limit(1);
    if (!lockedCurrent || lockedCurrent.agentId !== beforeLock.agentId) {
      throw new SecretRouteAuthorityConflict("route changed during update");
    }
    assertGovernedRouteUpdateIsSafe(lockedCurrent, allowedUpdates);
    // Partial-patch validation: skip per-host strictness here (the patch may not
    // carry method/path). The merged pass below enforces strict-host rules.
    const validationError = validateSecretRouteConfig(allowedUpdates, {
      enforceStrictHosts: false,
    });
    if (validationError) throw new Error(validationError);
    // Fail-closed: re-validate against the merged (existing ∪ update) config so a
    // partial edit can never loosen a strict host's narrowness rules (explicit
    // method + minimum path depth) for a route that already targets one.
    //
    // Exception: if the update leaves the route DISABLED, skip the merged
    // strict-host pass. A disabled route injects no credential, so strictness is
    // moot — and blocking it would prevent an admin from disabling a legacy
    // strict-host route that predates these rules (a safety-REDUCING action must
    // never be blocked by a stricter narrowness rule).
    const [current] = await db
      .select()
      .from(secretRoutes)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
      .limit(1);
    const willBeEnabled = allowedUpdates.enabled ?? current?.enabled ?? true;
    if (current && willBeEnabled) {
      const mergedValidationError = validateSecretRouteConfig({
        hostPattern: allowedUpdates.hostPattern ?? current.hostPattern ?? undefined,
        pathPattern: allowedUpdates.pathPattern ?? current.pathPattern ?? undefined,
        method: allowedUpdates.method ?? current.method ?? undefined,
        injectAs: allowedUpdates.injectAs ?? current.injectAs ?? undefined,
        injectKey: allowedUpdates.injectKey ?? current.injectKey ?? undefined,
        injectFormat: allowedUpdates.injectFormat ?? current.injectFormat ?? undefined,
      });
      if (mergedValidationError) throw new Error(mergedValidationError);
    }
    if (allowedUpdates.hostPattern !== undefined) {
      allowedUpdates.hostPattern = allowedUpdates.hostPattern.trim().toLowerCase();
    }
    if (allowedUpdates.pathPattern !== undefined) {
      allowedUpdates.pathPattern = allowedUpdates.pathPattern.trim();
    }
    if (allowedUpdates.method !== undefined) {
      allowedUpdates.method = allowedUpdates.method.trim().toUpperCase();
    }
    if (allowedUpdates.injectKey !== undefined) {
      allowedUpdates.injectKey = allowedUpdates.injectKey.trim();
    }
    if (allowedUpdates.agentId !== undefined) {
      const [agent] = await db
        .select({ id: agents.id })
        .from(agents)
        .where(and(eq(agents.id, allowedUpdates.agentId), eq(agents.tenantId, tenantId)));
      if (!agent) {
        throw new Error(`Agent ${allowedUpdates.agentId} not found for tenant ${tenantId}`);
      }
    }
    const [row] = await db
      .update(secretRoutes)
      .set(allowedUpdates)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
      .returning();
    if (row) {
      await assertNoOppositeAuthorityOverlap(db as never, {
        ...row,
        agentId: destinationAgentId,
      });
    }
    return row ?? null;
  }

  async deleteRoute(tenantId: string, routeId: string): Promise<boolean> {
    const db = getDb();
    const result = await db
      .delete(secretRoutes)
      .where(and(eq(secretRoutes.id, routeId), eq(secretRoutes.tenantId, tenantId)))
      .returning();
    return result.length > 0;
  }

  // ─── Private helpers ─────────────────────────────────────────────────────────

  private toMetadata(row: Secret): SecretMetadata {
    return {
      id: row.id,
      tenantId: row.tenantId,
      name: row.name,
      description: row.description,
      version: row.version,
      rotatedAt: row.rotatedAt,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }
}
