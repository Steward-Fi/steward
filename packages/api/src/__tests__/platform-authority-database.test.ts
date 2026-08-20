import { expect, test } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { __platformAuthorityEnvironmentForTests } from "../services/platform-authority-database";

test("platform database authority remains bound to overlapping runtime snapshots", async () => {
  const previousUrl = process.env.STEWARD_PLATFORM_DATABASE_URL;
  const previousRole = process.env.STEWARD_PLATFORM_DATABASE_ROLE;
  let releaseFirst!: () => void;
  const firstBlocked = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let firstReady!: () => void;
  const ready = new Promise<void>((resolve) => {
    firstReady = resolve;
  });
  try {
    const first = withRuntimeEnvironment(
      {
        STEWARD_DB_MODE: "postgres",
        STEWARD_PGLITE_MEMORY: "false",
        STEWARD_PLATFORM_DATABASE_URL: "postgresql://first.invalid/steward",
        STEWARD_PLATFORM_DATABASE_ROLE: "platform_first",
        DATABASE_DRIVER: "postgres-js",
      },
      async () => {
        firstReady();
        await firstBlocked;
        return __platformAuthorityEnvironmentForTests();
      },
    );
    await ready;
    process.env.STEWARD_PLATFORM_DATABASE_URL = "postgresql://hostile.invalid/steward";
    process.env.STEWARD_PLATFORM_DATABASE_ROLE = "hostile_process_role";
    const second = await withRuntimeEnvironment(
      {
        STEWARD_DB_MODE: "postgres",
        STEWARD_PGLITE_MEMORY: "false",
        STEWARD_PLATFORM_DATABASE_URL: "postgresql://second.invalid/steward",
        STEWARD_PLATFORM_DATABASE_ROLE: "platform_second",
        DATABASE_DRIVER: "neon-websocket",
      },
      async () => __platformAuthorityEnvironmentForTests(),
    );
    releaseFirst();
    expect(await first).toEqual({
      databaseMode: "postgres",
      pgliteMemory: "false",
      connectionString: "postgresql://first.invalid/steward",
      expectedRole: "platform_first",
      driver: "postgres-js",
    });
    expect(second).toEqual({
      databaseMode: "postgres",
      pgliteMemory: "false",
      connectionString: "postgresql://second.invalid/steward",
      expectedRole: "platform_second",
      driver: "neon-websocket",
    });
  } finally {
    if (previousUrl === undefined) delete process.env.STEWARD_PLATFORM_DATABASE_URL;
    else process.env.STEWARD_PLATFORM_DATABASE_URL = previousUrl;
    if (previousRole === undefined) delete process.env.STEWARD_PLATFORM_DATABASE_ROLE;
    else process.env.STEWARD_PLATFORM_DATABASE_ROLE = previousRole;
  }
});
