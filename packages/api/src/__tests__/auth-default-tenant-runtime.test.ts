import { describe, expect, test } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { defaultAuthTenantId } from "../services/default-auth-tenant";

describe("default auth tenant runtime binding", () => {
  test("keeps overlapping Worker request snapshots isolated", async () => {
    let releaseFirst!: () => void;
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted!: () => void;
    const firstDidStart = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });

    const first = withRuntimeEnvironment(
      { STEWARD_DEFAULT_TENANT_ID: "tenant-first" },
      async () => {
        firstStarted();
        await firstCanFinish;
        return defaultAuthTenantId();
      },
    );
    await firstDidStart;

    const second = withRuntimeEnvironment(
      { STEWARD_DEFAULT_TENANT_ID: "tenant-second" },
      async () => {
        expect(defaultAuthTenantId()).toBe("tenant-second");
        releaseFirst();
        return defaultAuthTenantId();
      },
    );

    expect(await Promise.all([first, second])).toEqual(["tenant-first", "tenant-second"]);
  });

  test("uses the literal default when the active binding is absent or blank", () => {
    expect(withRuntimeEnvironment({}, () => defaultAuthTenantId())).toBe("default");
    expect(
      withRuntimeEnvironment({ STEWARD_DEFAULT_TENANT_ID: "   " }, () => defaultAuthTenantId()),
    ).toBe("default");
  });
});
