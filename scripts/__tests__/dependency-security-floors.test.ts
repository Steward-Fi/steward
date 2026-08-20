import { expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "../..");
const manifests = [
  join(root, "package.json"),
  ...readdirSync(join(root, "packages"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(root, "packages", entry.name, "package.json"))
    .filter(existsSync),
];

test("every direct Drizzle dependency requires the patched identifier-escaping release", () => {
  const consumers: string[] = [];
  for (const manifest of manifests) {
    const pkg = JSON.parse(readFileSync(manifest, "utf8")) as {
      dependencies?: Record<string, string>;
      overrides?: Record<string, string>;
    };
    const declared = pkg.dependencies?.["drizzle-orm"];
    if (!declared) continue;
    consumers.push(manifest);
    expect(declared).toBe("^0.45.2");
  }

  const rootPackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    overrides?: Record<string, string>;
  };
  expect(consumers.length).toBeGreaterThan(0);
  expect(rootPackage.overrides?.["drizzle-orm"]).toBe("^0.45.2");
});
