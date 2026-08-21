import { describe, expect, test } from "bun:test";
import { runReleaseMigrations } from "../release-migrations";

describe("out-of-band release migrations", () => {
  test("applies core before every enabled plugin migration", async () => {
    const order: string[] = [];
    const result = await runReleaseMigrations({
      async runCore() {
        order.push("core");
        return { applied: ["0113_personal_tenant_account_lifecycle"] };
      },
      async runPlugins() {
        order.push("plugins");
        return [
          {
            pluginName: "capabilities",
            id: "capabilities",
            migrationsTable: "__drizzle_migrations_plugin_capabilities",
          },
        ];
      },
    });

    expect(order).toEqual(["core", "plugins"]);
    expect(result.applied).toEqual(["0113_personal_tenant_account_lifecycle"]);
    expect(result.plugins).toHaveLength(1);
  });

  test("never starts plugin migrations after a core failure", async () => {
    let pluginsStarted = false;
    await expect(
      runReleaseMigrations({
        async runCore() {
          throw new Error("core failed");
        },
        async runPlugins() {
          pluginsStarted = true;
          return [];
        },
      }),
    ).rejects.toThrow("core failed");
    expect(pluginsStarted).toBe(false);
  });
});
