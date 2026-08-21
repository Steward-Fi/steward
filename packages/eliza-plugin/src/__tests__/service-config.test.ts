import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StewardService } from "../services/StewardService.js";

const CONFIG_ENV_KEYS = [
  "STEWARD_API_URL",
  "STEWARD_API_KEY",
  "STEWARD_JWT",
  "STEWARD_AGENT_ID",
  "STEWARD_TENANT_ID",
  "STEWARD_AUTO_REGISTER",
  "STEWARD_FALLBACK_LOCAL",
] as const;

const savedEnv = new Map<string, string | undefined>();

function runtime(steward: Record<string, unknown> = {}, agentId?: string) {
  return {
    agentId,
    character: { name: "Config Test Agent", settings: { steward } },
  } as never;
}

function requestMethod(input: RequestInfo | URL, init?: RequestInit): string {
  return input instanceof Request ? input.method : (init?.method ?? "GET");
}

describe("StewardService fail-closed configuration", () => {
  beforeEach(() => {
    for (const key of CONFIG_ENV_KEYS) {
      savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    for (const key of CONFIG_ENV_KEYS) {
      const value = savedEnv.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    savedEnv.clear();
  });

  it.each([
    {
      name: "API URL",
      settings: {},
      agentId: undefined,
      diagnostic: "STEWARD_API_URL is required",
    },
    {
      name: "authentication",
      settings: { apiUrl: "http://localhost:3200", agentId: "agent-1" },
      agentId: undefined,
      diagnostic: "STEWARD_API_KEY or STEWARD_JWT is required",
    },
    {
      name: "agent identity",
      settings: { apiUrl: "http://localhost:3200", apiKey: "test-api-key" },
      agentId: undefined,
      diagnostic: "STEWARD_AGENT_ID or runtime agentId is required",
    },
  ])("disables before network access when $name is missing", async ({
    settings,
    agentId,
    diagnostic,
  }) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const service = await StewardService.start(runtime(settings, agentId));

    expect(service.getConfig()).toBeNull();
    expect(service.isConnected()).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    expect(warning).toHaveBeenCalledWith(expect.stringContaining(diagnostic));
    await expect(service.getBalance()).rejects.toThrow("Steward service not connected");
  });

  it("accepts explicit loopback development config without implicitly registering", async () => {
    const fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: false, error: "agent not found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const service = await StewardService.start(
      runtime({ apiUrl: "http://localhost:3200", bearerToken: "test-token" }, "runtime-agent"),
    );

    expect(service.getConfig()).toMatchObject({
      apiUrl: "http://localhost:3200",
      agentId: "runtime-agent",
      autoRegister: false,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls.map(([input, init]) => requestMethod(input, init))).toEqual(["GET"]);
  });

  it("requires tenant-scoped API-key authority when registration is opted in", async () => {
    process.env.STEWARD_API_URL = "https://api.steward.example";
    process.env.STEWARD_JWT = "agent-token";
    process.env.STEWARD_AGENT_ID = "agent-1";
    process.env.STEWARD_AUTO_REGISTER = "true";
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const service = await StewardService.start(runtime());

    expect(service.getConfig()).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
    expect(warning).toHaveBeenCalledWith(
      expect.stringContaining("auto-registration requires STEWARD_API_KEY and STEWARD_TENANT_ID"),
    );
  });

  it("registers only after explicit opt-in with tenant-scoped API-key authority", async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (requestMethod(input, init) === "GET") {
        return new Response(JSON.stringify({ ok: false, error: "agent not found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ ok: false, error: "registration rejected" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetch);
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    await StewardService.start(
      runtime({
        apiUrl: "https://api.steward.example",
        apiKey: "tenant-api-key",
        tenantId: "tenant-1",
        agentId: "agent-1",
        autoRegister: true,
      }),
    );

    expect(fetch.mock.calls.map(([input, init]) => requestMethod(input, init))).toEqual([
      "GET",
      "POST",
    ]);
  });

  it.each([
    "http://api.steward.example",
    "https://user:password@api.steward.example",
    "file:///tmp/steward.sock",
  ])("rejects unsafe production URL %s before network access", async (apiUrl) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      StewardService.start(runtime({ apiUrl, bearerToken: "test-token", agentId: "agent-1" })),
    ).rejects.toThrow(/apiUrl|http:\/\/|https:\/\/|localhost/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("reports an unavailable service without advertising local signing", async () => {
    process.env.STEWARD_FALLBACK_LOCAL = "true";
    const fetch = vi.fn(async () => {
      throw new Error("upstream unavailable; token=do-not-log-this");
    });
    vi.stubGlobal("fetch", fetch);
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);

    const service = await StewardService.start(
      runtime({
        apiUrl: "https://api.steward.example",
        bearerToken: "test-token",
        agentId: "agent-1",
      }),
    );

    expect(service.isConnected()).toBe(false);
    expect(service.getConfig()).not.toHaveProperty("fallbackLocal");
    expect(warning).toHaveBeenCalledWith("[Steward] Could not connect", expect.anything());
    expect(JSON.stringify(warning.mock.calls)).not.toContain("do-not-log-this");
    expect(info.mock.calls.flat().join(" ")).not.toMatch(/fallback|local signing/i);
    await expect(service.signMessage("hello")).rejects.toThrow("Steward service not connected");
  });
});
