/**
 * readSecretValue — onboarding value sources for `steward secret add|rotate`.
 *
 * Salvaged property from the sovereign-custody A2 lane: secret plaintext should
 * come from --file or stdin, not a flag (shell-history leak). --value still
 * works for backward compatibility but emits a loud warning.
 */

import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readSecretValue } from "../index";

describe("readSecretValue", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("reads from --file and strips a single trailing newline", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-secret-"));
    dirs.push(dir);
    const file = join(dir, "secret.txt");
    writeFileSync(file, "dummy-value-123\n");
    expect(readSecretValue({ file })).toBe("dummy-value-123");
  });

  it("preserves interior newlines from --file (only the trailing one is stripped)", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-secret-"));
    dirs.push(dir);
    const file = join(dir, "multiline.txt");
    writeFileSync(file, "line1\nline2\n");
    expect(readSecretValue({ file })).toBe("line1\nline2");
  });

  it("accepts --value for backward compatibility but warns about shell history", () => {
    const warn = spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(readSecretValue({ value: "legacy-flag-value" })).toBe("legacy-flag-value");
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain("shell history");
    } finally {
      warn.mockRestore();
    }
  });

  it("prefers --file over --value (no warning when a file is given)", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-secret-"));
    dirs.push(dir);
    const file = join(dir, "preferred.txt");
    writeFileSync(file, "from-file");
    const warn = spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(readSecretValue({ file, value: "from-flag" })).toBe("from-file");
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});
