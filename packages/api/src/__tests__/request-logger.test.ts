import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { requestLogger } from "../middleware/request-logger";

/**
 * SEC-015 regression: the global request logger must never write query
 * strings to logs — live one-time credentials flow through them
 * (`GET /auth/callback/email?token=…`, OAuth `?code=…&state=…`).
 */
describe("requestLogger (SEC-015)", () => {
  it("logs method + path + status but never the query string", async () => {
    const lines: string[] = [];
    const app = new Hono();
    app.use(
      "*",
      requestLogger((line) => lines.push(line)),
    );
    app.get("/auth/callback/email", (c) => c.json({ ok: true }));

    const res = await app.request("/auth/callback/email?token=super-secret-one-time-token");
    expect(res.status).toBe(200);

    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("<-- GET /auth/callback/email");
    expect(lines[1]).toMatch(/^--> GET \/auth\/callback\/email 200 /);
    for (const line of lines) {
      expect(line).not.toContain("super-secret-one-time-token");
      expect(line).not.toContain("?");
    }
  });

  it("defaults to console.log when no sink is provided", async () => {
    const app = new Hono();
    app.use("*", requestLogger());
    app.get("/x", (c) => c.json({ ok: true }));
    const res = await app.request("/x?a=1");
    expect(res.status).toBe(200);
  });
});
