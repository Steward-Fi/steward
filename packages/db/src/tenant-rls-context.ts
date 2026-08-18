import { is, type SQLWrapper, sql } from "drizzle-orm";
import { PgTransaction } from "drizzle-orm/pg-core";

declare const trustedTenantContextBrand: unique symbol;
const TENANT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const AUTHORITY_METHOD_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export type TenantRlsDriver = "postgres-js" | "pglite" | "neon-http" | "neon-websocket";

export interface AuthenticatedTenantAuthority {
  readonly tenantId: string;
  readonly method: string;
  readonly subject: string;
}

export interface InternalJobTenantAuthority {
  readonly tenantId: string;
  readonly job: string;
}

/**
 * A transaction capability issued by one TenantRlsAuthority. It cannot be
 * constructed, cloned, or accepted by a different authority instance.
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

export interface TenantRlsAuthorityVerifier<AuthenticatedProvenance, InternalJobProvenance> {
  resolveAuthenticatedPrincipal(
    provenance: AuthenticatedProvenance,
  ): AuthenticatedTenantAuthority | null;
  resolveInternalJob(provenance: InternalJobProvenance): InternalJobTenantAuthority | null;
}

export interface TenantRlsContextIssuer<AuthenticatedProvenance, InternalJobProvenance> {
  fromAuthenticatedPrincipal(provenance: AuthenticatedProvenance): TrustedTenantContext;
  forInternalJob(provenance: InternalJobProvenance): TrustedTenantContext;
}

export interface TenantTransactionExecutor {
  execute(query: SQLWrapper): Promise<unknown>;
}

export interface TenantTransactionalDatabase<Tx extends TenantTransactionExecutor> {
  transaction<T>(callback: (tx: Tx) => Promise<T>): Promise<T>;
}

export interface TenantRlsTransactions {
  run<Tx extends TenantTransactionExecutor, T>(
    db: TenantTransactionalDatabase<Tx>,
    driver: TenantRlsDriver,
    context: TrustedTenantContext,
    callback: (tx: Tx) => Promise<T>,
  ): Promise<T>;
}

export interface TenantRlsAuthority<AuthenticatedProvenance, InternalJobProvenance> {
  /** Retain this capability only in authenticated middleware and named job runners. */
  readonly issuer: TenantRlsContextIssuer<AuthenticatedProvenance, InternalJobProvenance>;
  /** This capability is safe to share with code that already receives a trusted context. */
  readonly transactions: TenantRlsTransactions;
}

function assertTenantId(tenantId: string): void {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error("RLS_TENANT_CONTEXT_INVALID");
}

function authenticatedContext(input: AuthenticatedTenantAuthority): TrustedTenantContext {
  assertTenantId(input.tenantId);
  if (
    !AUTHORITY_METHOD_PATTERN.test(input.method) ||
    input.subject.length === 0 ||
    input.subject.length > 255 ||
    /[\u0000-\u001f\u007f]/.test(input.subject)
  ) {
    throw new Error("RLS_TENANT_AUTHORITY_INVALID");
  }
  return Object.freeze({
    tenantId: input.tenantId,
    authority: Object.freeze({
      kind: "authenticated-principal" as const,
      method: input.method,
      subject: input.subject,
    }),
  }) as TrustedTenantContext;
}

function internalJobContext(input: InternalJobTenantAuthority): TrustedTenantContext {
  assertTenantId(input.tenantId);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.job)) {
    throw new Error("RLS_TENANT_JOB_INVALID");
  }
  return Object.freeze({
    tenantId: input.tenantId,
    authority: Object.freeze({ kind: "internal-job" as const, job: input.job }),
  }) as TrustedTenantContext;
}

export function assertTenantRlsDriver(driver: TenantRlsDriver): void {
  if (driver === "neon-http") {
    throw new Error(
      "RLS_TRANSACTION_UNSUPPORTED: neon-http has no callback transactions; use a transaction-capable Workers database transport",
    );
  }
}

function rowsOf(result: unknown): unknown[] {
  return Array.isArray(result) ? result : ((result as { rows?: unknown[] } | null)?.rows ?? []);
}

function contextTenantId(result: unknown): unknown {
  return (rowsOf(result)[0] as { tenant_id?: unknown } | undefined)?.tenant_id;
}

/**
 * Create one lexical authority boundary at application composition time. Keep
 * `issuer` in verified authentication middleware and named job runners; pass
 * only `transactions` and an already-issued context to tenant data access.
 */
export function createTenantRlsAuthority<AuthenticatedProvenance, InternalJobProvenance>(
  verifier: TenantRlsAuthorityVerifier<AuthenticatedProvenance, InternalJobProvenance>,
): TenantRlsAuthority<AuthenticatedProvenance, InternalJobProvenance> {
  const trustedContexts = new WeakSet<object>();

  function trust(context: TrustedTenantContext): TrustedTenantContext {
    trustedContexts.add(context);
    return context;
  }

  const issuer: TenantRlsContextIssuer<AuthenticatedProvenance, InternalJobProvenance> =
    Object.freeze({
      fromAuthenticatedPrincipal(provenance: AuthenticatedProvenance): TrustedTenantContext {
        const resolved = verifier.resolveAuthenticatedPrincipal(provenance);
        if (!resolved) throw new Error("RLS_TENANT_AUTHORITY_UNVERIFIED");
        return trust(authenticatedContext(resolved));
      },
      forInternalJob(provenance: InternalJobProvenance): TrustedTenantContext {
        const resolved = verifier.resolveInternalJob(provenance);
        if (!resolved) throw new Error("RLS_TENANT_JOB_UNVERIFIED");
        return trust(internalJobContext(resolved));
      },
    });

  const transactions: TenantRlsTransactions = Object.freeze({
    async run<Tx extends TenantTransactionExecutor, T>(
      db: TenantTransactionalDatabase<Tx>,
      driver: TenantRlsDriver,
      context: TrustedTenantContext,
      callback: (tx: Tx) => Promise<T>,
    ): Promise<T> {
      assertTenantRlsDriver(driver);
      if (!trustedContexts.has(context)) throw new Error("RLS_TENANT_CONTEXT_UNTRUSTED");
      assertTenantId(context.tenantId);
      // A nested Drizzle transaction is a savepoint. SET LOCAL would survive
      // this callback until the unknown outer transaction finishes.
      if (is(db, PgTransaction)) throw new Error("RLS_TENANT_TRANSACTION_NESTED");

      const outcome = await db.transaction(async (tx) => {
        // Reject session-scoped contamination before exposing the transaction.
        const prior = await tx.execute(
          sql`SELECT NULLIF(current_setting('steward.tenant_id', true), '') AS tenant_id`,
        );
        if (contextTenantId(prior) != null) {
          // Commit the cleanup before reporting failure. Throwing here would
          // roll it back and return the contaminated connection to the pool.
          await tx.execute(sql`SELECT set_config('steward.tenant_id', '', false)`);
          const cleared = await tx.execute(
            sql`SELECT NULLIF(current_setting('steward.tenant_id', true), '') AS tenant_id`,
          );
          if (contextTenantId(cleared) != null) {
            throw new Error("RLS_TENANT_CONTEXT_CLEAR_FAILED");
          }
          return { kind: "dirty" as const };
        }

        await tx.execute(sql`SELECT set_config('steward.tenant_id', ${context.tenantId}, true)`);
        const result = await tx.execute(
          sql`SELECT current_setting('steward.tenant_id', true) AS tenant_id`,
        );
        if (contextTenantId(result) !== context.tenantId) {
          throw new Error("RLS_TENANT_CONTEXT_NOT_BOUND");
        }
        return { kind: "ok" as const, value: await callback(tx) };
      });
      if (outcome.kind === "dirty") throw new Error("RLS_TENANT_CONTEXT_DIRTY");
      return outcome.value;
    },
  });

  return Object.freeze({ issuer, transactions });
}
