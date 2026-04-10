import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { StewardAuth } from "../auth.ts";

// ─── Mock storage ─────────────────────────────────────────────────────────────

class MockStorage {
  private store = new Map<string, string>();
  getItem(key: string): string | null { return this.store.get(key) ?? null; }
  setItem(key: string, value: string): void { this.store.set(key, value); }
  removeItem(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Create a minimal JWT-like token with exp claim */
function fakeJwt(payload: Record<string, unknown> = {}): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + 3600,
    address: "0x1234",
    tenantId: "test-tenant",
    userId: "user-1",
    email: "test@example.com",
    ...payload,
  }));
  return `${header}.${body}.fake-sig`;
}

function createAuthWithSession(storage: MockStorage, tenantId?: string): StewardAuth {
  const auth = new StewardAuth({
    baseUrl: "https://api.steward.fi",
    storage,
    tenantId,
  });
  // Pre-populate a session
  storage.setItem("steward_session_token", fakeJwt());
  storage.setItem("steward_refresh_token", "refresh-token-123");
  return auth;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

describe("StewardAuth multi-tenant", () => {
  let storage: MockStorage;

  beforeEach(() => {
    storage = new MockStorage();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe("tenantId in config", () => {
    test("getTenantId returns configured value", () => {
      const auth = new StewardAuth({
        baseUrl: "https://api.steward.fi",
        storage,
        tenantId: "my-app",
      });
      expect(auth.getTenantId()).toBe("my-app");
    });

    test("getTenantId returns undefined when not configured", () => {
      const auth = new StewardAuth({
        baseUrl: "https://api.steward.fi",
        storage,
      });
      expect(auth.getTenantId()).toBeUndefined();
    });
  });

  describe("listTenants", () => {
    test("fetches user tenants with auth header", async () => {
      const auth = createAuthWithSession(storage);
      const mockTenants = [
        { tenantId: "app-1", tenantName: "Babylon", role: "member", joinedAt: "2026-01-01" },
        { tenantId: "personal-user-1", tenantName: "Personal", role: "owner", joinedAt: "2026-01-01" },
      ];

      globalThis.fetch = mock(async (url: string | URL | Request) => {
        const urlStr = typeof url === "string" ? url : url.toString();
        expect(urlStr).toBe("https://api.steward.fi/user/me/tenants");
        return new Response(JSON.stringify({ ok: true, data: mockTenants }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;

      const result = await auth.listTenants();
      expect(result).toHaveLength(2);
      expect(result[0].tenantName).toBe("Babylon");
    });

    test("throws when not authenticated", async () => {
      const auth = new StewardAuth({
        baseUrl: "https://api.steward.fi",
        storage,
      });
      // No session stored
      await expect(auth.listTenants()).rejects.toThrow("Not authenticated");
    });
  });

  describe("joinTenant", () => {
    test("posts to join endpoint", async () => {
      const auth = createAuthWithSession(storage);

      globalThis.fetch = mock(async (url: string | URL | Request, init?: RequestInit) => {
        const urlStr = typeof url === "string" ? url : url.toString();
        expect(urlStr).toBe("https://api.steward.fi/user/me/tenants/babylon/join");
        expect(init?.method).toBe("POST");
        return new Response(JSON.stringify({
          ok: true,
          tenantId: "babylon",
          tenantName: "Babylon",
          role: "member",
          joinedAt: "2026-04-10",
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;

      const result = await auth.joinTenant("babylon");
      expect(result.tenantId).toBe("babylon");
      expect(result.role).toBe("member");
    });
  });

  describe("leaveTenant", () => {
    test("sends DELETE to leave endpoint", async () => {
      const auth = createAuthWithSession(storage);

      globalThis.fetch = mock(async (url: string | URL | Request, init?: RequestInit) => {
        const urlStr = typeof url === "string" ? url : url.toString();
        expect(urlStr).toBe("https://api.steward.fi/user/me/tenants/some-app/leave");
        expect(init?.method).toBe("DELETE");
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;

      await expect(auth.leaveTenant("some-app")).resolves.toBeUndefined();
    });
  });

  describe("switchTenant", () => {
    test("refreshes session with new tenantId", async () => {
      const auth = createAuthWithSession(storage);
      const newToken = fakeJwt({ tenantId: "new-app" });

      globalThis.fetch = mock(async (_url: string | URL | Request, init?: RequestInit) => {
        const body = JSON.parse(init?.body as string);
        expect(body.refreshToken).toBe("refresh-token-123");
        expect(body.tenantId).toBe("new-app");
        return new Response(JSON.stringify({
          ok: true,
          token: newToken,
          refreshToken: "new-refresh-token",
          expiresIn: 900,
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;

      const session = await auth.switchTenant("new-app");
      expect(session).not.toBeNull();
      expect(session?.tenantId).toBe("new-app");
      // Token should be stored
      expect(storage.getItem("steward_session_token")).toBe(newToken);
      expect(storage.getItem("steward_refresh_token")).toBe("new-refresh-token");
    });

    test("returns null when no refresh token", async () => {
      const auth = new StewardAuth({
        baseUrl: "https://api.steward.fi",
        storage,
      });
      // Store only access token, no refresh
      storage.setItem("steward_session_token", fakeJwt());

      const result = await auth.switchTenant("new-app");
      expect(result).toBeNull();
    });

    test("returns null when refresh fails", async () => {
      const auth = createAuthWithSession(storage);

      globalThis.fetch = mock(async () => {
        return new Response(JSON.stringify({ ok: false, error: "Invalid refresh token" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;

      const result = await auth.switchTenant("new-app");
      expect(result).toBeNull();
    });
  });
});
