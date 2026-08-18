import { afterEach, describe, expect, test } from "bun:test";
import { sql } from "drizzle-orm";
import { DATABASE_DEADLINE_EXCEEDED_MESSAGE, withDatabaseDeadline } from "../client";

const originalDriver = process.env.DATABASE_DRIVER;
const originalUrl = process.env.DATABASE_URL;
const originalNodeEnv = process.env.NODE_ENV;
const originalFetch = globalThis.fetch;

afterEach(() => {
  if (originalDriver === undefined) delete process.env.DATABASE_DRIVER;
  else process.env.DATABASE_DRIVER = originalDriver;
  if (originalUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalUrl;
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  globalThis.fetch = originalFetch;
});

describe("cancel-safe database deadlines", () => {
  test("aborts a stalled Neon fetch and exposes only the normalized error", async () => {
    process.env.DATABASE_DRIVER = "neon-http";
    process.env.DATABASE_URL = "postgresql://lease:secret@deadline.invalid/steward";
    process.env.NODE_ENV = "test";
    let observedSignal: AbortSignal | undefined;
    globalThis.fetch = (async (_url, init) => {
      observedSignal = init?.signal as AbortSignal;
      return new Promise<Response>((_resolve, reject) => {
        observedSignal?.addEventListener(
          "abort",
          () => reject(new DOMException("fixture included a secret query", "AbortError")),
          { once: true },
        );
      });
    }) as typeof fetch;

    const startedAt = Date.now();
    let caught: unknown;
    try {
      await withDatabaseDeadline(Date.now() + 1_100, (db) => db.execute(sql`select 1`));
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe(DATABASE_DEADLINE_EXCEEDED_MESSAGE);
    expect((caught as Error).message).not.toContain("secret");
    expect(observedSignal?.aborted).toBe(true);
    expect(Date.now() - startedAt).toBeLessThan(2_000);
  });
});
