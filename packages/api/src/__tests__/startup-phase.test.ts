import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  resolveStartupPhaseTimeoutMs,
  runStartupPhase,
  type StartupPhaseEvent,
} from "../startup-phase";

describe("bounded pre-listen startup phases", () => {
  test("keeps plugin migration discovery inside the bounded compose phase", () => {
    const source = readFileSync(new URL("../index.ts", import.meta.url), "utf8");
    const phaseStart = source.indexOf('runStartupPhase("compose"');
    const phaseEnd = source.indexOf("}));", phaseStart);
    const discovery = source.indexOf("getComposedPluginMigrationSources()", phaseStart);
    expect(phaseStart).toBeGreaterThanOrEqual(0);
    expect(discovery).toBeGreaterThan(phaseStart);
    expect(discovery).toBeLessThanOrEqual(phaseEnd);
  });

  test("uses an exact phase override and rejects invalid bounds", () => {
    expect(
      resolveStartupPhaseTimeoutMs("redis", {
        STEWARD_STARTUP_PHASE_TIMEOUT_MS: "5000",
        STEWARD_STARTUP_REDIS_TIMEOUT_MS: "17",
      }),
    ).toBe(17);
    expect(() =>
      resolveStartupPhaseTimeoutMs("custody", { STEWARD_STARTUP_CUSTODY_TIMEOUT_MS: "0" }),
    ).toThrow(/positive integer/);
  });

  test("emits ordered fixed diagnostics and rejects a stalled phase", async () => {
    const events: StartupPhaseEvent[] = [];
    await expect(
      runStartupPhase("rls", () => new Promise(() => undefined), {
        env: { STEWARD_STARTUP_RLS_TIMEOUT_MS: "5" },
        emit: (event) => events.push(event),
      }),
    ).rejects.toThrow('startup phase "rls" exceeded 5ms');
    expect(events.map(({ phase, state }) => `${phase}:${state}`)).toEqual([
      "rls:started",
      "rls:failed",
    ]);
    expect(events[1]?.diagnostic).toMatchObject({ errorClass: "Error", errorCode: null });
  });

  test("does not let a later phase start before its predecessor completes", async () => {
    const order: string[] = [];
    await runStartupPhase(
      "redis",
      async () => {
        order.push("redis-operation");
      },
      {
        env: { STEWARD_STARTUP_REDIS_TIMEOUT_MS: "100" },
        emit: ({ state }) => order.push(`redis-${state}`),
      },
    );
    await runStartupPhase(
      "auth-stores",
      async () => {
        order.push("auth-operation");
      },
      {
        env: { STEWARD_STARTUP_AUTH_STORES_TIMEOUT_MS: "100" },
        emit: ({ state }) => order.push(`auth-${state}`),
      },
    );
    expect(order).toEqual([
      "redis-started",
      "redis-operation",
      "redis-completed",
      "auth-started",
      "auth-operation",
      "auth-completed",
    ]);
  });

  test("does not rethrow provider-controlled diagnostics at top level", async () => {
    const events: StartupPhaseEvent[] = [];
    await expect(
      runStartupPhase("custody", () => Promise.reject(new Error("postgres://user:secret@host")), {
        env: { STEWARD_STARTUP_CUSTODY_TIMEOUT_MS: "100" },
        emit: (event) => events.push(event),
      }),
    ).rejects.toThrow('startup phase "custody" failed');
    expect(JSON.stringify(events)).not.toContain("secret");
  });
});
