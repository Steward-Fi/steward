import { describe, expect, test } from "bun:test";
import {
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { validateApiKey } from "@stwd/auth";
import {
  generateDemoApiKey,
  promoteDemoCredentials,
  rotateDemoCredentials,
  stageDemoCredentials,
} from "../demo-api-key";

function tempRoot(prefix: string): string {
  return realpathSync(mkdtempSync(join(tmpdir(), prefix)));
}

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

  test("stages owner-only tenant-bound credentials without replacing the canonical file", () => {
    const root = tempRoot("steward-demo-stage-");
    try {
      const path = join(root, "private", "demo.env");
      const oldKey = generateDemoApiKey().key;
      promoteDemoCredentials(stageDemoCredentials("waifu.fun", oldKey, path));
      const nextKey = generateDemoApiKey().key;
      const pending = stageDemoCredentials("waifu.fun", nextKey, path);
      expect(lstatSync(dirname(path)).mode & 0o777).toBe(0o700);
      expect(lstatSync(pending.pendingPath).mode & 0o777).toBe(0o600);
      expect(readFileSync(path, "utf8")).toContain(`STEWARD_API_KEY=${oldKey}`);
      expect(readFileSync(pending.pendingPath, "utf8")).toBe(
        `STEWARD_TENANT_ID=waifu.fun\nSTEWARD_API_KEY=${nextKey}\n`,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("keeps prior and pending credentials on a pre-commit failure", async () => {
    const root = tempRoot("steward-demo-precommit-");
    try {
      const path = join(root, "demo.env");
      const oldKey = generateDemoApiKey().key;
      promoteDemoCredentials(stageDemoCredentials("waifu.fun", oldKey, path));
      const nextKey = generateDemoApiKey().key;
      const operation = rotateDemoCredentials(
        "waifu.fun",
        nextKey,
        async () => {
          throw new Error("database canary");
        },
        path,
      );
      await expect(operation).rejects.toThrow("rotation outcome is uncertain");
      const error = await operation.catch((caught) => (caught as Error).message);
      expect(error).not.toContain("database canary");
      expect(readFileSync(path, "utf8")).toContain(`STEWARD_API_KEY=${oldKey}`);
      const pending = readdirSync(root).find((name) => name.includes(".pending-"));
      expect(pending).toBeTruthy();
      expect(readFileSync(join(root, pending!), "utf8")).toContain(`STEWARD_API_KEY=${nextKey}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("retains the committed credential when atomic promotion fails", async () => {
    const root = tempRoot("steward-demo-postcommit-");
    try {
      const path = join(root, "demo.env");
      const oldKey = generateDemoApiKey().key;
      promoteDemoCredentials(stageDemoCredentials("waifu.fun", oldKey, path));
      const nextKey = generateDemoApiKey().key;
      let committed = false;
      const operation = rotateDemoCredentials(
        "waifu.fun",
        nextKey,
        async () => {
          committed = true;
        },
        path,
        () => {
          throw new Error("rename canary");
        },
      );
      await expect(operation).rejects.toThrow("Credential hash committed");
      const error = await operation.catch((caught) => (caught as Error).message);
      expect(committed).toBe(true);
      expect(error).not.toContain("rename canary");
      expect(readFileSync(path, "utf8")).toContain(`STEWARD_API_KEY=${oldKey}`);
      const pending = readdirSync(root).find((name) => name.includes(".pending-"));
      expect(readFileSync(join(root, pending!), "utf8")).toContain(`STEWARD_API_KEY=${nextKey}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("promotes only after a successful commit", async () => {
    const root = tempRoot("steward-demo-success-");
    try {
      const path = join(root, "demo.env");
      const nextKey = generateDemoApiKey().key;
      let committed = false;
      expect(
        await rotateDemoCredentials(
          "waifu.fun",
          nextKey,
          async () => {
            committed = true;
          },
          path,
        ),
      ).toBe(path);
      expect(committed).toBe(true);
      expect(readFileSync(path, "utf8")).toContain(`STEWARD_API_KEY=${nextKey}`);
      expect(readdirSync(root).some((name) => name.includes(".pending-"))).toBe(false);
      expect(readdirSync(root).some((name) => name.includes(".promote-"))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects redirected parents and replaces file symlinks rather than following them", () => {
    const root = tempRoot("steward-demo-links-");
    try {
      const real = join(root, "real");
      const canonical = join(real, "demo.env");
      promoteDemoCredentials(
        stageDemoCredentials("waifu.fun", generateDemoApiKey().key, canonical),
      );
      const linkedParent = join(root, "linked-parent");
      symlinkSync(real, linkedParent);
      expect(() =>
        stageDemoCredentials("other", generateDemoApiKey().key, join(linkedParent, "other.env")),
      ).toThrow("redirected directories");

      const linkedFile = join(root, "linked.env");
      symlinkSync(canonical, linkedFile);
      const pending = stageDemoCredentials("waifu.fun", generateDemoApiKey().key, linkedFile);
      promoteDemoCredentials(pending);
      expect(lstatSync(linkedFile).isSymbolicLink()).toBe(false);
      expect(readFileSync(canonical, "utf8")).not.toBe(readFileSync(linkedFile, "utf8"));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
