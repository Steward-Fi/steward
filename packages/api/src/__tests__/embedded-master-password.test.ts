import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateEmbeddedMasterPassword } from "../services/embedded-master-password";

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "steward-embedded-password-"));
  dirs.push(dir);
  return dir;
}

describe("embedded master password persistence", () => {
  it("creates a mode-0600 password and reuses it", () => {
    const dir = tempDir();
    const first = loadOrCreateEmbeddedMasterPassword(dir);
    const second = loadOrCreateEmbeddedMasterPassword(dir);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toBe(first);
    expect(readFileSync(join(dir, ".master-password"), "utf8").trim()).toBe(first);
    expect(statSync(join(dir, ".master-password")).mode & 0o777).toBe(0o600);
  });

  it("rejects a symlink instead of reading or overwriting its target", () => {
    const dir = tempDir();
    const target = join(dir, "target");
    writeFileSync(target, `${"a".repeat(64)}\n`);
    symlinkSync(target, join(dir, ".master-password"));
    expect(() => loadOrCreateEmbeddedMasterPassword(dir)).toThrow();
    expect(readFileSync(target, "utf8")).toBe(`${"a".repeat(64)}\n`);
  });
});
