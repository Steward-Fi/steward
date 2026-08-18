/**
 * Pluggable database client for Steward.
 *
 * Selects a driver based on the `DATABASE_DRIVER` env var:
 *   - "postgres-js"  (default)  — long-lived TCP pool via the `postgres` package.
 *                                  Used by Bun/Node entry points.
 *   - "neon-http"                — HTTP-only fetch driver via @neondatabase/serverless.
 *                                  Used by Cloudflare Workers (no TCP, no pools).
 *   - PGLite                     — in-process WASM, set via setPGLiteOverride()
 *                                  from the embedded/desktop entry point.
 *
 * Per-request usage on Workers
 * ────────────────────────────
 * Workers cannot share a TCP pool across isolates. For Workers code, prefer
 * `createDbForRequest(env)` and stash the result on `c.var.db` via middleware.
 * The neon-http driver is fetch-based and safe to instantiate per request.
 *
 * Singleton usage (Bun/Node)
 * ──────────────────────────
 * `getDb()` keeps a single Drizzle instance per process.
 *   - postgres-js: pool of 10 connections, prepare:false
 *   - neon-http  : creates one fetch-based client and reuses it
 */

import { drizzle as drizzleNeon, type NeonHttpDatabase } from "drizzle-orm/neon-http";
import { drizzle as drizzlePostgres, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import type { PGLiteDb } from "./pglite";

import * as schema from "./schema";
import * as schemaAuth from "./schema-auth";

declare const process: {
  env: Record<string, string | undefined>;
};

export type DatabaseDriver = "postgres-js" | "neon-http";

const FULL_SCHEMA = { ...schema, ...schemaAuth };
type FullSchema = typeof FULL_SCHEMA;

export function getDatabaseDriver(): DatabaseDriver {
  const raw = process.env.DATABASE_DRIVER?.trim().toLowerCase();
  if (raw === "neon-http") return "neon-http";
  return "postgres-js";
}

export function getDatabaseUrl(): string {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }

  assertDatabaseUrlTls(connectionString);
  return connectionString;
}

/**
 * Refuse to start in production if DATABASE_URL is not using authenticated TLS.
 * Localhost connections are exempt. STEWARD_ALLOW_INSECURE_DB=true is a separate
 * acknowledgement for intentionally plaintext private-network deployments.
 *
 * SEC-087: postgres-js treats `sslmode=require` as TLS WITHOUT server certificate
 * verification — the connection is encrypted but MITM-able on a hostile network.
 * Only `verify-ca` / `verify-full` (with `sslrootcert`) authenticate the peer.
 * `require` is accepted only with STEWARD_ALLOW_UNVERIFIED_DB_TLS=true, which
 * deliberately acknowledges encryption without peer authentication.
 */
export function assertDatabaseUrlTls(connectionString: string): void {
  if (process.env.NODE_ENV !== "production") return;

  const allowInsecure = process.env.STEWARD_ALLOW_INSECURE_DB === "true";
  const allowUnverifiedTls = process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS === "true";
  let parsed: URL;
  try {
    parsed = new URL(connectionString);
  } catch {
    if (allowInsecure) {
      console.warn(
        "[db] WARNING: STEWARD_ALLOW_INSECURE_DB=true — DATABASE_URL is not a valid URL, so TLS cannot be verified.",
      );
      return;
    }
    throw new Error(
      "DATABASE_URL must be a valid URL so TLS settings can be verified in production",
    );
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error("DATABASE_URL must use the postgres:// or postgresql:// scheme");
  }

  const host = parsed.hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return;

  // Parse the query parameter instead of substring-matching the raw URL. A
  // password/path such as `.../sslmode=require` must not satisfy the check,
  // and duplicate sslmode parameters are ambiguous across client parsers.
  const sslModes = parsed.searchParams.getAll("sslmode").map((value) => value.toLowerCase());
  const hasTls =
    sslModes.length === 1 && ["require", "verify-ca", "verify-full"].includes(sslModes[0]);
  if (hasTls) {
    if (sslModes[0] === "require") {
      if (!allowUnverifiedTls) {
        throw new Error(
          "DATABASE_URL sslmode=require does not authenticate the database server in " +
            "production. Use sslmode=verify-full (recommended) or explicitly set " +
            "STEWARD_ALLOW_UNVERIFIED_DB_TLS=true to acknowledge this MITM risk.",
        );
      }
      console.warn(
        "[db] WARNING: STEWARD_ALLOW_UNVERIFIED_DB_TLS=true permits sslmode=require, which " +
          "encrypts the database connection without authenticating the server. Use " +
          "sslmode=verify-full for production (SEC-087).",
      );
    }
    return;
  }

  if (allowInsecure) {
    console.warn(
      "[db] WARNING: STEWARD_ALLOW_INSECURE_DB=true — DATABASE_URL has no sslmode=require. " +
        "This is only safe on a private network. SOC2 CC6.7 requires encryption in transit.",
    );
    return;
  }

  throw new Error(
    "DATABASE_URL must include sslmode=verify-full (recommended) or sslmode=verify-ca in production. " +
      "Set STEWARD_ALLOW_INSECURE_DB=true to override for private-network deployments.",
  );
}

export function createPostgresClient(connectionString = getDatabaseUrl()) {
  assertDatabaseUrlTls(connectionString);
  return postgres(connectionString, {
    max: 10,
    prepare: false,
  });
}

export const DATABASE_DEADLINE_EXCEEDED_MESSAGE = "database operation deadline exceeded";
const DATABASE_DEADLINE_CLEANUP_GRACE_MS = 100;

export class DatabaseDeadlineExceededError extends Error {
  constructor() {
    super(DATABASE_DEADLINE_EXCEEDED_MESSAGE);
    this.name = "DatabaseDeadlineExceededError";
  }
}

function deadlineMilliseconds(deadlineAt: number): number {
  if (!Number.isSafeInteger(deadlineAt)) throw new Error("database deadline must be an integer");
  const remaining = deadlineAt - Date.now();
  if (remaining < 1_000) throw new DatabaseDeadlineExceededError();
  return remaining;
}

function serverDeadlineConnectionParameters(remainingMs: number) {
  // Let PostgreSQL cancel first. The driver-level timer below is the hard stop
  // for connect/acquisition stalls and retains a small window for the server's
  // cancellation response to reach the client before its socket is destroyed.
  const serverMs = Math.max(1, remainingMs - DATABASE_DEADLINE_CLEANUP_GRACE_MS);
  return {
    statement_timeout: serverMs,
    lock_timeout: serverMs,
    idle_in_transaction_session_timeout: serverMs,
  };
}

function withServerDeadlineInUrl(connectionString: string, remainingMs: number): string {
  const parsed = new URL(connectionString);
  const existing = parsed.searchParams.get("options")?.trim();
  const serverMs = Math.max(1, remainingMs - DATABASE_DEADLINE_CLEANUP_GRACE_MS);
  const limits = [
    `-c statement_timeout=${serverMs}`,
    `-c lock_timeout=${serverMs}`,
    `-c idle_in_transaction_session_timeout=${serverMs}`,
  ].join(" ");
  parsed.searchParams.set("options", existing ? `${existing} ${limits}` : limits);
  return parsed.toString();
}

function isDatabaseDeadlineError(error: unknown): boolean {
  if (error instanceof DatabaseDeadlineExceededError) return true;
  let current = error;
  for (let depth = 0; depth < 5 && current && typeof current === "object"; depth += 1) {
    const candidate = current as { code?: unknown; name?: unknown; cause?: unknown };
    if (
      candidate.code === "57014" ||
      candidate.code === "55P03" ||
      candidate.code === "25P03" ||
      candidate.code === "CONNECT_TIMEOUT" ||
      candidate.name === "AbortError" ||
      candidate.name === "TimeoutError"
    ) {
      return true;
    }
    current = candidate.cause;
  }
  return false;
}

/**
 * Run one database unit of work under an absolute, cancel-safe deadline.
 *
 * postgres-js uses a fresh max=1 client: there is no unbounded shared-pool
 * queue, connect_timeout covers DNS/TCP/TLS/authentication, PostgreSQL enforces
 * statement/lock/idle-in-transaction limits, and the absolute timer closes the
 * driver connection. postgres-js settles active queries only after that close,
 * so an open transaction is rolled back before this function rejects.
 *
 * neon-http uses a per-call AbortSignal and the same server parameters. Its HTTP
 * response can stall independently of PostgreSQL, so the fetch abort is the hard
 * transport bound while the earlier server limit protects transaction atomicity.
 */
export async function withDatabaseDeadline<T>(
  deadlineAt: number,
  use: (db: ReturnType<typeof createDb>["db"]) => Promise<T>,
): Promise<T> {
  const remainingMs = deadlineMilliseconds(deadlineAt);

  if (pgliteOverride) {
    // Embedded PGLite has no network/pool and no cancel API. Keep the same
    // phase-start contract without pretending that WASM execution is abortable.
    return use(pgliteOverride.db as ReturnType<typeof createDb>["db"]);
  }

  if (getDatabaseDriver() === "neon-http") {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remainingMs);
    try {
      const { db } = createNeonHttpDb(withServerDeadlineInUrl(getDatabaseUrl(), remainingMs), {
        signal: controller.signal,
      });
      return await use(db as unknown as ReturnType<typeof createDb>["db"]);
    } catch (error) {
      if (controller.signal.aborted || isDatabaseDeadlineError(error)) {
        throw new DatabaseDeadlineExceededError();
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  const client = postgres(getDatabaseUrl(), {
    max: 1,
    prepare: false,
    connect_timeout: Math.max(1, Math.floor(remainingMs / 1_000)),
    connection: serverDeadlineConnectionParameters(remainingMs),
  });
  const db = drizzlePostgres(client, { schema: FULL_SCHEMA });
  let deadlineClose: Promise<void> | undefined;
  const timer = setTimeout(() => {
    // This is driver cancellation, not an abandoned Promise.race. Destroying
    // the sole connection makes PostgreSQL roll back any open transaction and
    // rejects its query before `use` can settle.
    deadlineClose = client.end({ timeout: 0 });
  }, remainingMs);
  try {
    return await use(db);
  } catch (error) {
    if (deadlineClose || Date.now() >= deadlineAt || isDatabaseDeadlineError(error)) {
      if (deadlineClose) await deadlineClose.catch(() => undefined);
      throw new DatabaseDeadlineExceededError();
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (deadlineClose) await deadlineClose.catch(() => undefined);
    else await client.end({ timeout: 0 });
  }
}

// ─── postgres-js (Bun/Node) ───────────────────────────────────────────────────

export function createDb(connectionString = getDatabaseUrl()) {
  const client = createPostgresClient(connectionString);
  const db = drizzlePostgres(client, { schema: FULL_SCHEMA });

  return { client, db };
}

// ─── neon-http (Cloudflare Workers) ───────────────────────────────────────────

/**
 * Create a Drizzle instance backed by Neon's HTTP fetch driver.
 *
 * Suitable for stateless runtimes (Cloudflare Workers, edge functions).
 * Each call returns a fresh client; for per-request use this is intentional —
 * the underlying transport is HTTP, so there is no TCP connection to reuse.
 */
export function createNeonHttpDb(
  connectionString = getDatabaseUrl(),
  options: { signal?: AbortSignal } = {},
) {
  assertDatabaseUrlTls(connectionString);
  // Lazy-require so Bun/Node entry points don't pull @neondatabase/serverless
  // into their bundle when the postgres-js driver is in use.
  const { neon } = require("@neondatabase/serverless") as {
    neon: (url: string, options?: Record<string, unknown>) => any;
  };
  const client = neon(connectionString, {
    fetchOptions: options.signal ? { signal: options.signal } : undefined,
  });
  const db = drizzleNeon(client, { schema: FULL_SCHEMA });
  return { client, db };
}

/**
 * Build a Drizzle instance from Worker `env` bindings. Intended to be wired
 * into a per-request Hono middleware:
 *
 *   app.use("*", async (c, next) => {
 *     c.set("db", createDbForRequest(c.env));
 *     await next();
 *   });
 *
 * @param env  An object with a DATABASE_URL string field. Workers pass in the
 *             whole `env` binding object.
 */
export function createDbForRequest(env: { DATABASE_URL?: string }) {
  const url = env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL binding is required for createDbForRequest()");
  return createNeonHttpDb(url).db;
}

// ─── PGLite support ───────────────────────────────────────────────────────────
// When running in embedded/local mode, the PGLite adapter sets these overrides
// so all existing code that calls getDb()/closeDb() works unchanged.

let pgliteOverride:
  | {
      db: ReturnType<typeof createDb>["db"] | PGLiteDb;
      close: () => Promise<void>;
    }
  | undefined;

/**
 * Set PGLite as the backing database. Called by the embedded entry point
 * BEFORE any route code runs.
 */
export function setPGLiteOverride(
  db: ReturnType<typeof createDb>["db"] | PGLiteDb,
  close: () => Promise<void>,
) {
  pgliteOverride = { db, close };
}

// ─── Global singleton ─────────────────────────────────────────────────────────

type GlobalDbHandle =
  | {
      driver: "postgres-js";
      client: ReturnType<typeof postgres>;
      db: PostgresJsDatabase<FullSchema>;
    }
  | {
      driver: "neon-http";
      client: ReturnType<typeof createNeonHttpDb>["client"];
      db: NeonHttpDatabase<FullSchema>;
    };

let globalDb: GlobalDbHandle | undefined;

function buildGlobalDb(): GlobalDbHandle {
  const driver = getDatabaseDriver();
  if (driver === "neon-http") {
    const { client, db } = createNeonHttpDb();
    return { driver: "neon-http", client, db };
  }
  const { client, db } = createDb();
  return { driver: "postgres-js", client, db };
}

export function getDb() {
  if (pgliteOverride) return pgliteOverride.db as ReturnType<typeof createDb>["db"];
  globalDb ??= buildGlobalDb();
  // Both postgres-js and neon-http drivers expose the same Drizzle surface
  // for our schema; we type the public return as the postgres-js variant so
  // callers don't have to branch on driver type at every call site.
  return globalDb.db as unknown as ReturnType<typeof createDb>["db"];
}

/**
 * Return the raw SQL tagged-template client.
 *
 * Both `postgres` (postgres-js) and `neon` (neon-http) expose a tagged-template
 * call signature that returns the result rows directly. The two clients differ
 * in their full surface (e.g. `client.end()`, transactions), so callers that
 * need driver-specific features should branch on `getDatabaseDriver()`.
 *
 * `auth_kv_store` (packages/auth/src/store-backends.ts) only uses the tagged
 * template, which is portable across both.
 */
export function getSql() {
  if (pgliteOverride) {
    throw new Error("getSql() is not available in PGLite mode — use getDb() instead");
  }
  globalDb ??= buildGlobalDb();
  return globalDb.client;
}

export async function closeDb() {
  if (pgliteOverride) {
    await pgliteOverride.close();
    pgliteOverride = undefined;
    return;
  }

  if (!globalDb) {
    return;
  }

  if (globalDb.driver === "postgres-js") {
    await globalDb.client.end();
  }
  // neon-http has no persistent connection to close.

  globalDb = undefined;
}

export type Database = ReturnType<typeof getDb>;
