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

export class DatabaseDeadlineExceededError extends Error {
  readonly code = "database_deadline_exceeded";

  constructor() {
    super("database operation timed out");
    this.name = "DatabaseDeadlineExceededError";
  }
}

export type DeadlineDb = ReturnType<typeof createDb>["db"];

const MIN_DATABASE_DEADLINE_MS = 25;
const MAX_DATABASE_DEADLINE_MS = 30_000;

function checkedDeadlineMs(deadlineAt: number): number {
  if (!Number.isFinite(deadlineAt)) throw new DatabaseDeadlineExceededError();
  const remaining = Math.floor(deadlineAt - Date.now());
  if (remaining < MIN_DATABASE_DEADLINE_MS) throw new DatabaseDeadlineExceededError();
  return Math.min(remaining, MAX_DATABASE_DEADLINE_MS);
}

function isDatabaseTimeout(error: unknown): boolean {
  if (error instanceof DatabaseDeadlineExceededError) return true;
  if (!error || typeof error !== "object") return false;
  const value = error as { name?: unknown; code?: unknown };
  return (
    value.name === "AbortError" ||
    value.name === "TimeoutError" ||
    value.code === "57014" ||
    value.code === "CONNECT_TIMEOUT"
  );
}

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

export function createPostgresClient(
  connectionString = getDatabaseUrl(),
  options: { max?: number; connectTimeoutSeconds?: number } = {},
) {
  assertDatabaseUrlTls(connectionString);
  return postgres(connectionString, {
    max: options.max ?? 10,
    prepare: false,
    ...(options.connectTimeoutSeconds === undefined
      ? {}
      : { connect_timeout: options.connectTimeoutSeconds }),
  });
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
    neon: (url: string, options?: { fetchOptions?: Record<string, unknown> }) => any;
  };
  const client = neon(connectionString, {
    fetchOptions: {
      ...(options.signal ? { signal: options.signal } : {}),
    },
  });
  const db = drizzleNeon(client, { schema: FULL_SCHEMA });
  return { client, db };
}

/**
 * Run a database phase inside a cancel-safe wall-clock deadline.
 *
 * postgres-js uses a fresh single-connection client for each bounded phase.
 * Its connect timeout therefore covers connection establishment/acquisition,
 * while PostgreSQL's server-enforced `statement_timeout` cancels statements.
 * Drizzle transactions opened by the callback inherit that server timeout;
 * postgres-js observes the cancellation and completes rollback before the
 * transaction promise rejects.
 *
 * neon-http has no pooled connection to acquire. Its per-phase AbortSignal is
 * passed to the actual fetch request and the timer is kept alive until the
 * request has settled. A timeout is always normalized and never exposes SQL,
 * parameters, hosts, or provider diagnostics.
 */
export async function withDatabaseDeadline<T>(
  deadlineAt: number,
  fn: (db: DeadlineDb) => Promise<T>,
  options: {
    driver?: DatabaseDriver;
    connectionString?: string;
  } = {},
): Promise<T> {
  const budgetMs = checkedDeadlineMs(deadlineAt);
  const driver = options.driver ?? getDatabaseDriver();
  const connectionString = options.connectionString ?? getDatabaseUrl();

  if (driver === "neon-http") {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), budgetMs);
    try {
      const { db } = createNeonHttpDb(connectionString, {
        signal: controller.signal,
      });
      return await fn(db as unknown as DeadlineDb);
    } catch (error) {
      if (controller.signal.aborted || isDatabaseTimeout(error)) {
        throw new DatabaseDeadlineExceededError();
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  const client = createPostgresClient(connectionString, {
    max: 1,
    connectTimeoutSeconds: Math.max(0.025, budgetMs / 1_000),
  });
  let expired = false;
  const timer = setTimeout(() => {
    expired = true;
    // This client is dedicated to the bounded phase and is never returned to a
    // shared pool. Closing it cancels any in-flight statement and makes a later
    // query fail immediately if the callback was idle when the deadline hit.
    void client.end({ timeout: 0 }).catch(() => undefined);
  }, budgetMs);
  try {
    const remainingMs = checkedDeadlineMs(deadlineAt);
    // max:1 makes this setup query acquire the only connection. Every later
    // query/transaction in fn uses that same session and inherits the timeout.
    await client`select set_config('statement_timeout', ${`${remainingMs}ms`}, false)`;
    const db = drizzlePostgres(client, { schema: FULL_SCHEMA });
    return await fn(db as unknown as DeadlineDb);
  } catch (error) {
    if (expired || Date.now() >= deadlineAt || isDatabaseTimeout(error)) {
      throw new DatabaseDeadlineExceededError();
    }
    throw error;
  } finally {
    clearTimeout(timer);
    await client.end({ timeout: 1 }).catch(() => undefined);
  }
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
