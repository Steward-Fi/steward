import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../config.js";

/**
 * SEC-188: a config file that EXISTS but does not parse must fail fast instead
 * of silently starting on defaults (apiKey "", localhost API). A MISSING file
 * stays supported (env-only configuration).
 */

const TOUCHED_ENV = [
  "CONFIG_PATH",
  "STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS",
  "STEWARD_API_URL",
  "STEWARD_TENANT_ID",
  "STEWARD_API_KEY",
  "WEBHOOK_PORT",
  "DRY_RUN",
] as const;

let savedEnv: Record<string, string | undefined>;
let dir: string;

beforeEach(() => {
  savedEnv = Object.fromEntries(TOUCHED_ENV.map((k) => [k, process.env[k]]));
  for (const k of TOUCHED_ENV) delete process.env[k];
  dir = mkdtempSync(join(tmpdir(), "agent-trader-config-test-"));
});

afterEach(() => {
  for (const k of TOUCHED_ENV) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("loadConfig (SEC-188)", () => {
  it("throws when the config file exists but does not parse", () => {
    const path = join(dir, "agent-trader.config.json");
    writeFileSync(path, "{ not json !!");
    process.env.CONFIG_PATH = path;

    expect(() => loadConfig()).toThrow(/exists but could not be parsed/);
  });

  it("still supports a missing config file (env-only configuration)", () => {
    process.env.CONFIG_PATH = join(dir, "does-not-exist.json");
    process.env.STEWARD_AGENT_TRADER_ALLOW_UNSIGNED_WEBHOOKS = "true";

    const config = loadConfig();
    expect(config.agents).toEqual([]);
    expect(config.steward.apiUrl).toBe("http://localhost:3200");
  });

  it("loads a valid config file", () => {
    const path = join(dir, "agent-trader.config.json");
    writeFileSync(path, JSON.stringify({ webhookSecret: "s", agents: [], dryRun: true }));
    process.env.CONFIG_PATH = path;

    const config = loadConfig();
    expect(config.webhookSecret).toBe("s");
    expect(config.dryRun).toBe(true);
  });
});
