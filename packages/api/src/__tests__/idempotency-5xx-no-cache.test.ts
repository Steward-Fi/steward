import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { idempotencyMiddleware, MemoryIdempotencyStore } from "../middleware/idempotency";
import type { ApiResponse, AppVariables } from "../services/context";

const AUTHORIZATION = "Bearer idempotency-5xx-test-token";

// Regression for Steward-Fi/steward#103: the global idempotency middleware must
// NOT cache a transient 5xx response as a permanent, replayable "completed"
// outcome — that poisons every legitimate retry of the same Idempotency-Key for
// the full TTL. A handler that *returns* a 5xx should release the reservation so
// a retry re-executes.
describe("idempotencyMiddleware 5xx handling", () => {
  function makeApp(statusByCall: number[]) {
    const app = new Hono<{ Variables: AppVariables }>();
    const store = new MemoryIdempotencyStore(100);
    let count = 0;

    app.use("*", async (c, next) => {
      c.set("authType", "api-key");
      await next();
    });
    app.use("*", idempotencyMiddleware({ store, ttlMs: 60_000 }));
    app.post("/mutate", (c) => {
      const status = statusByCall[count] ?? 200;
      count += 1;
      if (status >= 400) {
        return c.json<ApiResponse>({ ok: false, error: "store unavailable" }, status as 503);
      }
      return c.json({ ok: true, count });
    });

    return { app, getCount: () => count };
  }

  const init = {
    method: "POST",
    headers: {
      Authorization: AUTHORIZATION,
      "Content-Type": "application/json",
      "Idempotency-Key": "idem-key-5xx",
    },
    body: JSON.stringify({ value: "first" }),
  };

  it("does not cache a returned 503 and lets a retry re-execute the handler", async () => {
    // First call returns 503 (transient), second call returns 200.
    const { app, getCount } = makeApp([503, 200]);

    const first = await app.request("/mutate", init);
    expect(first.status).toBe(503);
    // The 5xx ran fresh; it is not a replay.
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(await first.json()).toEqual({ ok: false, error: "store unavailable" });

    // Same key, same request — without the fix this replays the cached 503.
    const second = await app.request("/mutate", init);
    expect(second.status).toBe(200);
    expect(second.headers.get("Idempotency-Replayed")).toBe("false");
    expect(await second.json()).toEqual({ ok: true, count: 2 });

    // Handler executed twice: the 503 was not cached as a permanent outcome.
    expect(getCount()).toBe(2);
  });

  it("still caches and replays a successful 2xx response", async () => {
    const { app, getCount } = makeApp([200]);

    const first = await app.request("/mutate", init);
    const second = await app.request("/mutate", init);

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.headers.get("Idempotency-Replayed")).toBe("false");
    expect(second.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await first.json()).toEqual({ ok: true, count: 1 });
    expect(await second.json()).toEqual({ ok: true, count: 1 });
    // Only the first call reached the handler; the second was replayed.
    expect(getCount()).toBe(1);
  });
});
