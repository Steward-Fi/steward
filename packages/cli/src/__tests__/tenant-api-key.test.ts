/**
 * readTenantApiKey — credential sources for `steward tenant create`.
 *
 * The tenant API key is a plaintext credential: it should arrive via
 * --api-key-file, --api-key-env, or stdin, never as an argv flag that lands in
 * shell history and `ps` output. --api-key still works for backward
 * compatibility but emits a loud warning (same treatment as readSecretValue).
 */

import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readTenantApiKey } from "../index";

describe("readTenantApiKey", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
    delete process.env.STEWARD_TEST_TENANT_KEY;
  });

  it("reads from --api-key-file and strips a single trailing newline", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-tenant-key-"));
    dirs.push(dir);
    const file = join(dir, "tenant.key");
    writeFileSync(file, "stw_tenant_abc123\n");
    expect(readTenantApiKey({ "api-key-file": file })).toBe("stw_tenant_abc123");
  });

  it("reads from --api-key-env and refuses an unset variable", () => {
    process.env.STEWARD_TEST_TENANT_KEY = "stw_tenant_fromenv";
    expect(readTenantApiKey({ "api-key-env": "STEWARD_TEST_TENANT_KEY" })).toBe(
      "stw_tenant_fromenv",
    );
    delete process.env.STEWARD_TEST_TENANT_KEY;
    expect(() => readTenantApiKey({ "api-key-env": "STEWARD_TEST_TENANT_KEY" })).toThrow(
      "unset or empty",
    );
  });

  it("accepts --api-key for backward compatibility but warns about shell history", () => {
    const warn = spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(readTenantApiKey({ "api-key": "legacy-flag-key" })).toBe("legacy-flag-key");
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain("shell history");
    } finally {
      warn.mockRestore();
    }
  });

  it("prefers --api-key-file over --api-key (no warning when a file is given)", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-tenant-key-"));
    dirs.push(dir);
    const file = join(dir, "preferred.key");
    writeFileSync(file, "from-file");
    const warn = spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(readTenantApiKey({ "api-key-file": file, "api-key": "from-flag" })).toBe("from-file");
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});
