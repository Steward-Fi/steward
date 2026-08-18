import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("check-attestation bounded registry ingestion", () => {
  test("rejects a registry file over 4 MiB before JSON parsing or network access", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-attestation-"));
    const registryPath = join(directory, "oversized.json");
    try {
      writeFileSync(registryPath, Buffer.alloc(4 * 1024 * 1024 + 1, 0x20));
      const result = Bun.spawnSync([process.execPath, "scripts/check-attestation.ts"], {
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

      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(
        "measurement registry file exceeded the 4 MiB ingestion limit",
      );
      expect(result.stderr.toString()).not.toContain("fetch");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
