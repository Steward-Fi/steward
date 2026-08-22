import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "../..");
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agent-trader-startup-test-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("agent-trader startup configuration", () => {
  it("exits before starting services when an enabled agent has no API key", () => {
    const configPath = join(dir, "agent-trader.config.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        webhookSecret: "test-secret",
        agents: [
          {
            agentId: "agent-1",
            tokenAddress: "0x0000000000000000000000000000000000000001",
            strategy: "manual",
            intervalSeconds: 60,
            enabled: true,
            params: {},
          },
        ],
      }),
    );

    const result = Bun.spawnSync({
      cmd: [process.execPath, "src/index.ts"],
      cwd: packageRoot,
      env: {
        ...process.env,
        CONFIG_PATH: configPath,
        STEWARD_API_KEY: "",
        NODE_ENV: "test",
      },
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(result.exitCode).toBe(1);
    const stderr = result.stderr.toString();
    expect(stderr).toContain("Failed to load configuration");
    expect(result.stdout.toString()).not.toContain("Configuration loaded");
  });
});
