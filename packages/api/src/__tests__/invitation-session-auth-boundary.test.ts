import { beforeAll, describe, expect, test } from "bun:test";

const TEST_JWT_SECRET = "steward-invitation-api-boundary-secret-2026";
const CLAIM = "a".repeat(64);

process.env.STEWARD_JWT_SECRET = TEST_JWT_SECRET;
process.env.DATABASE_URL = "pglite://embedded";
process.env.STEWARD_DB_MODE = "pglite";

let signAccessToken: typeof import("@stwd/auth")["signAccessToken"];
let verifyToken: typeof import("@stwd/auth")["verifyToken"];
let userRoutes: typeof import("../routes/user")["userRoutes"];

beforeAll(async () => {
  ({ signAccessToken, verifyToken } = await import("@stwd/auth"));
  ({ userRoutes } = await import("../routes/user"));
});

describe("invitation session authentication boundary", () => {
  test("production authority mints a complete session and rejects a tampered bearer", async () => {
    const token = await signAccessToken(
      {
        address: "",
        email: "user-a@example.test",
        role: "owner",
        tenantId: "tenant-a",
        tenantRole: "owner",
        userId: "user-a",
      },
      "1h",
    );
    const payload = await verifyToken(token);

    expect(payload).toMatchObject({
      iss: "steward",
      aud: "steward-api",
      tenantId: "tenant-a",
      userId: "user-a",
    });
    expect(payload.jti).toEqual(expect.any(String));

    const finalCharacter = token.at(-1);
    const tampered = `${token.slice(0, -1)}${finalCharacter === "a" ? "b" : "a"}`;
    await expect(verifyToken(tampered)).rejects.toThrow();

    // Use the mounted production route group, including userSessionAuth. The
    // bad signature must fail before invitation or database work can execute.
    const response = await userRoutes.request("/me/tenants/tenant-a/invitations/accept", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tampered}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: CLAIM }),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({
      ok: false,
      error: "Invalid or expired session token",
    });
  });
});
