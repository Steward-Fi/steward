import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function runCheck(registryPath: string) {
  return Bun.spawnSync([process.execPath, "scripts/check-attestation.ts"], {
    cwd: join(import.meta.dir, "../.."),
    env: {
      ...process.env,
      STEWARD_ATTESTATION_ENDPOINT: "http://127.0.0.1:1/never-requested",
      STEWARD_MEASUREMENT_REGISTRY: registryPath,
      STEWARD_REGISTRY_ALLOW_UNPINNED: "true",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
}

describe("check-attestation bounded registry ingestion", () => {
  test("rejects a registry file over 4 MiB before JSON parsing or network access", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-attestation-"));
    const registryPath = join(directory, "oversized.json");
    try {
      writeFileSync(registryPath, Buffer.alloc(4 * 1024 * 1024 + 1, 0x20));
      const result = runCheck(registryPath);

      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(
        "measurement registry file exceeded the 4 MiB ingestion limit",
      );
      expect(result.stderr.toString()).not.toContain("fetch");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("rejects malformed UTF-8 before network access", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-attestation-"));
    const registryPath = join(directory, "invalid-utf8.json");
    try {
      writeFileSync(registryPath, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x7d]));
      const result = runCheck(registryPath);

      expect(result.exitCode).toBe(2);
      expect(result.stderr.toString()).toContain("not valid UTF-8 JSON");
      expect(result.stderr.toString()).not.toContain("fetch");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
