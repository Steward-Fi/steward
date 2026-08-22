import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import {
  bootTimeoutMs,
  installBootDeadline,
  migrationPhaseTimeoutMs,
  runStartupPhase,
  startupPhaseTimeoutMs,
} from "../services/startup-phase";

const originalPhaseTimeout = process.env.STEWARD_STARTUP_PHASE_TIMEOUT_MS;
const originalBootTimeout = process.env.STEWARD_BOOT_TIMEOUT_MS;
const originalMigrationTimeout = process.env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS;

afterEach(() => {
  if (originalPhaseTimeout === undefined) delete process.env.STEWARD_STARTUP_PHASE_TIMEOUT_MS;
  else process.env.STEWARD_STARTUP_PHASE_TIMEOUT_MS = originalPhaseTimeout;
  if (originalBootTimeout === undefined) delete process.env.STEWARD_BOOT_TIMEOUT_MS;
  else process.env.STEWARD_BOOT_TIMEOUT_MS = originalBootTimeout;
  if (originalMigrationTimeout === undefined)
    delete process.env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS;
  else process.env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS = originalMigrationTimeout;
  mock.restore();
});

describe("bounded startup phases", () => {
  test("emits ordered phase markers without logging task results", async () => {
    const log = spyOn(console, "log").mockImplementation(() => undefined);
    await expect(runStartupPhase("redis", async () => "secret-result", 100)).resolves.toBe(
      "secret-result",
    );
    expect(log.mock.calls.map((call) => String(call[0]))).toEqual([
      "[steward:start] phase=redis state=begin",
      expect.stringMatching(/^\[steward:start\] phase=redis state=complete durationMs=\d+$/),
    ]);
    expect(JSON.stringify(log.mock.calls)).not.toContain("secret-result");
  });

  test("rejects a stalled phase at its explicit deadline", async () => {
    spyOn(console, "error").mockImplementation(() => undefined);
    await expect(
      runStartupPhase("migrations", () => new Promise(() => undefined), 10),
    ).rejects.toThrow("startup phase migrations exceeded 10ms");
  });

  test("validates configurable phase and overall boot deadlines", () => {
    process.env.STEWARD_STARTUP_PHASE_TIMEOUT_MS = "0";
    process.env.STEWARD_BOOT_TIMEOUT_MS = "not-a-number";
    process.env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS = "-1";
    expect(() => startupPhaseTimeoutMs()).toThrow("must be a positive integer");
    expect(() => bootTimeoutMs()).toThrow("must be a positive integer");
    expect(() => migrationPhaseTimeoutMs()).toThrow("must be a positive integer");
  });

  test("the overall boot deadline invokes the fail-closed callback", async () => {
    process.env.STEWARD_BOOT_TIMEOUT_MS = "10";
    const onTimeout = mock(() => undefined);
    const cancel = installBootDeadline(onTimeout);
    await Bun.sleep(20);
    cancel();
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });
});
