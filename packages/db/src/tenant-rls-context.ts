import { sql } from "drizzle-orm";

const trustedTenantContextBrand: unique symbol = Symbol("steward.trusted-tenant-context");
const TENANT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type TenantRlsDriver = "postgres-js" | "pglite" | "neon-http";

/**
 * An application-internal capability minted only after authentication or by a
 * named background job. Request headers and body fields are not valid inputs to
 * the transaction helper.
 */
export interface TrustedTenantContext {
  readonly tenantId: string;
  readonly authority:
    | {
        readonly kind: "authenticated-principal";
        readonly method: string;
        readonly subject: string;
      }
    | { readonly kind: "internal-job"; readonly job: string };
  readonly [trustedTenantContextBrand]: true;
}

function assertTenantId(tenantId: string): void {
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    throw new Error("RLS_TENANT_CONTEXT_INVALID");
  }
}

export function tenantContextFromAuthenticatedPrincipal(input: {
  tenantId: string;
  method: string;
  subject: string;
}): TrustedTenantContext {
  assertTenantId(input.tenantId);
  if (!input.method || !input.subject) throw new Error("RLS_TENANT_AUTHORITY_INVALID");
  return Object.freeze({
    tenantId: input.tenantId,
    authority: Object.freeze({
      kind: "authenticated-principal" as const,
      method: input.method,
      subject: input.subject,
    }),
    [trustedTenantContextBrand]: true as const,
  });
}

export function tenantContextForInternalJob(input: {
  tenantId: string;
  job: string;
}): TrustedTenantContext {
  assertTenantId(input.tenantId);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.job)) {
    throw new Error("RLS_TENANT_JOB_INVALID");
  }
  return Object.freeze({
    tenantId: input.tenantId,
    authority: Object.freeze({ kind: "internal-job" as const, job: input.job }),
    [trustedTenantContextBrand]: true as const,
  });
}

export function assertTenantRlsDriver(driver: TenantRlsDriver): void {
  if (driver === "neon-http") {
    throw new Error(
      "RLS_TRANSACTION_UNSUPPORTED: neon-http has no callback transactions; use a transaction-capable Workers database transport",
    );
  }
}

interface TenantTransactionExecutor {
  execute(query: unknown): Promise<unknown>;
}

interface TenantTransactionalDatabase<Tx extends TenantTransactionExecutor> {
  transaction<T>(callback: (tx: Tx) => Promise<T>): Promise<T>;
}

function hasTrustedBrand(context: TrustedTenantContext): boolean {
  return context[trustedTenantContextBrand] === true;
}

/**
 * Run one tenant unit of work on one checked-out connection. `set_config(...,
 * true)` is transaction-local, so commit, rollback, and pool reuse clear the
 * context. Never replace this with session-level SET on a pooled connection.
 */
export async function withTenantRlsTransaction<Tx extends TenantTransactionExecutor, T>(
  db: TenantTransactionalDatabase<Tx>,
  driver: TenantRlsDriver,
  context: TrustedTenantContext,
  callback: (tx: Tx) => Promise<T>,
): Promise<T> {
  assertTenantRlsDriver(driver);
  if (!hasTrustedBrand(context)) throw new Error("RLS_TENANT_CONTEXT_UNTRUSTED");
  assertTenantId(context.tenantId);

  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('steward.tenant_id', ${context.tenantId}, true)`);
    const result = await tx.execute(
      sql`SELECT current_setting('steward.tenant_id', true) AS tenant_id`,
    );
    const rows = Array.isArray(result)
      ? result
      : ((result as { rows?: unknown[] } | null)?.rows ?? []);
    const tenantId = (rows[0] as { tenant_id?: unknown } | undefined)?.tenant_id;
    if (tenantId !== context.tenantId) throw new Error("RLS_TENANT_CONTEXT_NOT_BOUND");
    return callback(tx);
  });
}
