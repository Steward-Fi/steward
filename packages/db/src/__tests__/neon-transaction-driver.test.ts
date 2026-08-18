import { afterEach, describe, expect, test } from "bun:test";
import {
  __buildNeonTransactionPoolConfigForTests,
  createDbForRequest,
  createNeonTransactionDbForRequest,
  getDatabaseDriver,
} from "../client";

const originalDriver = process.env.DATABASE_DRIVER;

afterEach(() => {
  if (originalDriver === undefined) delete process.env.DATABASE_DRIVER;
  else process.env.DATABASE_DRIVER = originalDriver;
});

describe("transaction-capable Workers database driver", () => {
  test("recognizes the explicit transaction-capable driver", () => {
    process.env.DATABASE_DRIVER = "neon-websocket";
    expect(getDatabaseDriver()).toBe("neon-websocket");
  });

  test("does not silently route a request-scoped socket through the legacy helper", () => {
    expect(() =>
      createDbForRequest({
        DATABASE_DRIVER: " neon-websocket ",
        DATABASE_URL: "postgresql://example.invalid/steward",
      }),
    ).toThrow("RLS_TRANSACTION_HANDLE_REQUIRED");
  });

  test("also rejects process-level socket selection for non-Worker callers", () => {
    process.env.DATABASE_DRIVER = "neon-websocket";
    expect(() =>
      createDbForRequest({ DATABASE_URL: "postgresql://example.invalid/steward" }),
    ).toThrow("RLS_TRANSACTION_HANDLE_REQUIRED");
  });

  test("does not let an empty binding bypass process-level socket selection", () => {
    process.env.DATABASE_DRIVER = "neon-websocket";
    expect(() =>
      createDbForRequest({
        DATABASE_DRIVER: "   ",
        DATABASE_URL: "postgresql://example.invalid/steward",
      }),
    ).toThrow("RLS_TRANSACTION_HANDLE_REQUIRED");
  });

  test("rejects unknown request driver bindings instead of silently using HTTP", () => {
    expect(() =>
      createDbForRequest({
        DATABASE_DRIVER: "bogus",
        DATABASE_URL: "postgresql://example.invalid/steward",
      }),
    ).toThrow("DATABASE_DRIVER_UNSUPPORTED");
  });

  test("requires explicit driver selection before opening a socket", () => {
    expect(() =>
      createNeonTransactionDbForRequest({
        DATABASE_DRIVER: "neon-http",
        DATABASE_URL: "postgresql://example.invalid/steward",
      }),
    ).toThrow("RLS_TRANSACTION_DRIVER_REQUIRED");
  });

  test("uses Worker bindings as the production TLS authority", () => {
    // Cloudflare's checked-in bindings do not define NODE_ENV. The transaction
    // transport must therefore default to production enforcement, not skip it.
    expect(() =>
      createNeonTransactionDbForRequest({
        DATABASE_DRIVER: "neon-websocket",
        DATABASE_URL: "postgresql://db.example.test/steward",
      }),
    ).toThrow("DATABASE_URL must include sslmode=verify-full");

    expect(() =>
      createNeonTransactionDbForRequest({
        DATABASE_DRIVER: "neon-websocket",
        DATABASE_URL: "postgresql://db.example.test/steward",
        NODE_ENV: "production",
      }),
    ).toThrow("DATABASE_URL must include sslmode=verify-full");

    expect(() =>
      createNeonTransactionDbForRequest({
        DATABASE_DRIVER: "neon-websocket",
        DATABASE_URL: "postgresql://db.example.test/steward?sslmode=require",
        NODE_ENV: "production",
      }),
    ).toThrow("does not authenticate the database server");
  });

  test("bounds connection, query, lock, statement, and idle transaction phases", () => {
    const config = __buildNeonTransactionPoolConfigForTests({
      DATABASE_DRIVER: "neon-websocket",
      DATABASE_URL: "postgresql://db.example.test/steward?sslmode=verify-full",
      NODE_ENV: "production",
    });
    expect(config.max).toBe(1);
    expect(config.connectionTimeoutMillis).toBe(10_000);
    expect(config.idleTimeoutMillis).toBe(30_000);
    expect(config.query_timeout).toBe(30_000);
    expect(config.statement_timeout).toBe(29_900);
    expect(config.lock_timeout).toBe(29_900);
    expect(config.idle_in_transaction_session_timeout).toBe(29_900);
    const options = new URL(config.connectionString).searchParams.get("options") ?? "";
    expect(options).toContain("statement_timeout=29900");
    expect(options).toContain("lock_timeout=29900");
    expect(options).toContain("idle_in_transaction_session_timeout=29900");
  });

  test("returns an explicitly closeable request handle with idempotent cleanup", async () => {
    const handle = createNeonTransactionDbForRequest({
      DATABASE_DRIVER: "neon-websocket",
      DATABASE_URL: "postgresql://example.invalid/steward",
      NODE_ENV: "test",
    });
    expect(handle.driver).toBe("neon-websocket");
    expect(typeof handle.db.transaction).toBe("function");
    await Promise.all([handle.close(), handle.close()]);
  });
});
