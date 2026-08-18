import { afterEach, describe, expect, test } from "bun:test";
import {
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

  test("returns an explicitly closeable request handle with idempotent cleanup", async () => {
    const handle = createNeonTransactionDbForRequest({
      DATABASE_DRIVER: "neon-websocket",
      DATABASE_URL: "postgresql://example.invalid/steward",
    });
    expect(handle.driver).toBe("neon-websocket");
    expect(typeof handle.db.transaction).toBe("function");
    await Promise.all([handle.close(), handle.close()]);
  });
});
