import { describe, expect, test } from "bun:test";
import { lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { validateApiKey } from "../../../auth/src/api-keys";
import { generateDemoApiKey, writeDemoCredentials } from "../demo-api-key";

describe("demo API key", () => {
  test("is fresh, high-entropy, and verifies only against its own hash", () => {
    const first = generateDemoApiKey();
    const second = generateDemoApiKey();

    expect(first.key).toMatch(/^stw_[0-9a-f]{32}$/);
    expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(second.key).not.toBe(first.key);
    expect(validateApiKey(first.key, first.hash)).toBe(true);
    expect(validateApiKey(second.key, first.hash)).toBe(false);
  });

  test("writes tenant-bound credentials owner-only and rejects symlink targets", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-demo-credentials-"));
    try {
      const pair = generateDemoApiKey();
      const path = join(root, "private", "demo.env");
      expect(writeDemoCredentials("waifu.fun", pair.key, path)).toBe(path);
      expect(lstatSync(dirname(path)).mode & 0o777).toBe(0o700);
      expect(lstatSync(path).mode & 0o777).toBe(0o600);
      expect(readFileSync(path, "utf8")).toBe(
        `STEWARD_TENANT_ID=waifu.fun\nSTEWARD_API_KEY=${pair.key}\n`,
      );

      const symlink = join(root, "linked.env");
      symlinkSync(path, symlink);
      expect(() => writeDemoCredentials("other", pair.key, symlink)).toThrow();
      expect(readFileSync(path, "utf8")).toContain("STEWARD_TENANT_ID=waifu.fun");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
