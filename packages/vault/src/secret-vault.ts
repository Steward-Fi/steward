/**
 * Secret Vault — encrypted credential storage for tenant API keys and secrets.
 *
 * Reuses the KeyStore's AES-256-GCM encryption. Secrets are encrypted per-tenant
 * using the same master key hierarchy as wallet keys.
 *
 * Decrypted values are NEVER returned via API — only used internally for
 * credential injection into proxied requests.
 */

import { isIP } from "node:net";
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

const DEFAULT_SECRET_ROUTE_HOSTS = [
  "api.openai.com",
  "api.anthropic.com",
  "public-api.birdeye.so",
  "api.coingecko.com",
  "api.helius.xyz",
];
const BLOCKED_INJECT_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const VALID_PROXY_METHODS = new Set(["*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
const MAX_SECRET_INJECT_FORMAT_LENGTH = 255;
const MAX_SECRET_ROUTE_PRIORITY = 1_000_000;

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

type SecretRouteConfig = {
  agentId?: string;
  hostPattern?: string;
  pathPattern?: string;
  method?: string;
  injectAs?: string;
  injectKey?: string;
  injectFormat?: string;
  priority?: number;
};

function configuredSecretRouteHosts(): string[] {
  return [
    ...DEFAULT_SECRET_ROUTE_HOSTS,
    ...(process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  ];
}

function hostAllowedByEntry(hostPattern: string, allowedHost: string): boolean {
  if (hostPattern === allowedHost) return true;
  if (hostPattern.startsWith("*.")) {
    const suffix = hostPattern.slice(2);
    const suffixLabels = suffix.split(".").filter(Boolean);
    if (suffixLabels.length < 2) return false;
    if (!allowedHost.startsWith("*.")) return false;
    const allowedSuffix = allowedHost.slice(2);
    return suffix === allowedSuffix || suffix.endsWith(`.${allowedSuffix}`);
  }
  if (allowedHost.startsWith("*.")) {
    const allowedSuffix = allowedHost.slice(1);
    return hostPattern.endsWith(allowedSuffix) && hostPattern.length > allowedSuffix.length;
  }
  return false;
}

function validateSecretRouteConfig(input: SecretRouteConfig): string | null {
  if (input.agentId !== undefined && !input.agentId.trim()) return "agentId is invalid";

  if (input.hostPattern !== undefined) {
    const hostPattern = input.hostPattern.trim().toLowerCase();
    if (!hostPattern || hostPattern === "*" || hostPattern === "*.*") {
      return "hostPattern must be an explicit allowed host";
    }
    const hostForIpCheck = hostPattern.startsWith("*.") ? hostPattern.slice(2) : hostPattern;
    if (
      isIP(hostForIpCheck) ||
      hostForIpCheck === "localhost" ||
      hostForIpCheck.endsWith(".localhost") ||
      hostForIpCheck.endsWith(".local") ||
      hostForIpCheck.endsWith(".internal")
    ) {
      return "hostPattern must not target localhost, private, or internal hosts";
    }
    if (!configuredSecretRouteHosts().some((allowed) => hostAllowedByEntry(hostPattern, allowed))) {
      return "hostPattern is not in the secret route allowlist";
    }
  }

  if (input.pathPattern !== undefined) {
    const pathPattern = input.pathPattern.trim();
    const lowered = pathPattern.toLowerCase();
    if (!pathPattern.startsWith("/")) return "pathPattern must start with /";
    if (
      process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES !== "true" &&
      (pathPattern === "/*" || pathPattern === "*")
    ) {
      return "broad pathPattern requires STEWARD_ALLOW_BROAD_SECRET_ROUTES=true";
    }
    if (/[\u0000-\u001f\u007f\\]/.test(pathPattern)) return "pathPattern is invalid";
    if (
      lowered.includes("%2e") ||
      lowered.includes("%2f") ||
      lowered.includes("%5c") ||
      pathPattern.split("/").some((segment) => segment === "." || segment === "..")
    ) {
      return "pathPattern must not contain dot segments or encoded path separators";
    }
  }

  if (input.method !== undefined) {
    const method = input.method.trim().toUpperCase();
    if (!VALID_PROXY_METHODS.has(method)) return "method is not allowed";
    if (process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES !== "true" && method === "*") {
      return "broad method requires STEWARD_ALLOW_BROAD_SECRET_ROUTES=true";
    }
  }

  if (input.injectAs !== undefined) {
    if (!["header", "query"].includes(input.injectAs)) {
      return "'injectAs' must be one of: header, query";
    }
    if (input.injectAs === "query" && process.env.STEWARD_ALLOW_QUERY_SECRET_INJECTION !== "true") {
      return "query credential injection requires STEWARD_ALLOW_QUERY_SECRET_INJECTION=true";
    }
  }

  if (input.injectKey !== undefined) {
    const key = input.injectKey.trim().toLowerCase();
    if (!key || /[\r\n:]/.test(key)) return "injectKey is invalid";
    if (BLOCKED_INJECT_HEADERS.has(key)) return `injectKey '${input.injectKey}' is not allowed`;
  }

  if (input.injectFormat !== undefined) {
    if (input.injectFormat.length > MAX_SECRET_INJECT_FORMAT_LENGTH) {
      return `injectFormat cannot exceed ${MAX_SECRET_INJECT_FORMAT_LENGTH} characters`;
    }
    if (/[\r\n]/.test(input.injectFormat)) return "injectFormat must not contain line breaks";
    const placeholderCount = input.injectFormat.match(/\{value\}/g)?.length ?? 0;
    if (placeholderCount !== 1) {
      return "injectFormat must contain exactly one {value} placeholder";
    }
  }

  if (
    input.priority !== undefined &&
    (!Number.isSafeInteger(input.priority) ||
      input.priority < 0 ||
      input.priority > MAX_SECRET_ROUTE_PRIORITY)
  ) {
    return `priority must be an integer between 0 and ${MAX_SECRET_ROUTE_PRIORITY}`;
  }

  return null;
}

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
   * Decrypt a secret for internal use (credential injection). NEVER expose via API.
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

    // Check expiration
    if (row.expiresAt && row.expiresAt < new Date()) {
      throw new Error(`Secret ${secretId} has expired`);
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
    },
  ): Promise<SecretRoute> {
    const db = getDb();
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
    const secret = await this.getSecretById(tenantId, secretId);
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
      })
      .returning();

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
    }>,
  ): Promise<SecretRoute | null> {
    const db = getDb();
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
    ] as const) {
      if (updates[key] !== undefined) allowedUpdates[key] = updates[key] as never;
    }
    if (Object.keys(allowedUpdates).length === 0) {
      return this.getRoute(tenantId, routeId);
    }
    const validationError = validateSecretRouteConfig(allowedUpdates);
    if (validationError) throw new Error(validationError);
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
