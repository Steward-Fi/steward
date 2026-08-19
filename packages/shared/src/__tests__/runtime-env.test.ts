import { expect, test } from "bun:test";
import { runtimeEnvironmentValue, withRuntimeEnvironment } from "../runtime-env";

test("runtime environments remain isolated across overlapping asynchronous work", async () => {
  const previous = process.env.RUNTIME_ENV_POISON;
  process.env.RUNTIME_ENV_POISON = "global";
  try {
    let releaseFirst!: () => void;
    let firstStarted!: () => void;
    const firstReady = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    const firstCanRead = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const first = withRuntimeEnvironment({ REQUEST_VALUE: "first" }, async () => {
      firstStarted();
      await firstCanRead;
      return {
        value: runtimeEnvironmentValue("REQUEST_VALUE"),
        poison: runtimeEnvironmentValue("RUNTIME_ENV_POISON"),
      };
    });
    const second = withRuntimeEnvironment({ REQUEST_VALUE: "second" }, async () => {
      await firstReady;
      const result = {
        value: runtimeEnvironmentValue("REQUEST_VALUE"),
        poison: runtimeEnvironmentValue("RUNTIME_ENV_POISON"),
      };
      releaseFirst();
      return result;
    });

    expect(await Promise.all([first, second])).toEqual([
      { value: "first", poison: undefined },
      { value: "second", poison: undefined },
    ]);
    expect(runtimeEnvironmentValue("RUNTIME_ENV_POISON")).toBe("global");
  } finally {
    if (previous === undefined) delete process.env.RUNTIME_ENV_POISON;
    else process.env.RUNTIME_ENV_POISON = previous;
  }
});
