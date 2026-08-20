import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditArchiveVerificationMode } from "../index";

describe("audit archive verification trust mode", () => {
  it("requires an independent fingerprint for a trusted --verify claim", () => {
    expect(() => auditArchiveVerificationMode({ verify: true })).toThrow(
      "--verify requires --fp from an independent trusted channel",
    );
    expect(
      auditArchiveVerificationMode({ verify: true, fp: "a".repeat(64), "key-id": "archive-v1" }),
    ).toEqual({ mode: "trusted", fingerprint: "a".repeat(64), keyId: "archive-v1" });
    expect(() => auditArchiveVerificationMode({ fp: "a".repeat(64) })).toThrow(
      "--fp and --key-id require --verify",
    );
    expect(() => auditArchiveVerificationMode({ "key-id": "archive-v1" })).toThrow(
      "--fp and --key-id require --verify",
    );
    expect(() => auditArchiveVerificationMode({ verify: true, fp: "not-hex" })).toThrow(
      "exactly 64 hexadecimal",
    );
    expect(() =>
      auditArchiveVerificationMode({ verify: true, fp: "a".repeat(64), "key-id": "bad key" }),
    ).toThrow("--key-id is invalid");
  });

  it("makes embedded-key checking an explicit integrity-only mode", () => {
    expect(auditArchiveVerificationMode({ "integrity-only": true })).toEqual({
      mode: "integrity-only",
      keyId: undefined,
    });
    expect(() =>
      auditArchiveVerificationMode({ verify: true, "integrity-only": true, fp: "a".repeat(64) }),
    ).toThrow("mutually exclusive");
    expect(() =>
      auditArchiveVerificationMode({ "integrity-only": true, fp: "a".repeat(64) }),
    ).toThrow("Use --verify with --fp");
  });

  it("the offline verifier bounds manifest reads and rejects symlinks and FIFOs", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-archive-verifier-"));
    const verifier = join(import.meta.dir, "../../../../scripts/verify-audit-archive.mjs");
    const run = (manifest: string) =>
      spawnSync(process.execPath, [verifier, manifest, directory, "--integrity-only"], {
        encoding: "utf8",
        timeout: 2_000,
      });
    try {
      const oversized = join(directory, "oversized.json");
      writeFileSync(oversized, Buffer.alloc(1024 * 1024 + 1));
      const oversizedResult = run(oversized);
      expect(oversizedResult.status).toBe(1);
      expect(oversizedResult.stderr).toContain("1048576 byte limit");

      const small = join(directory, "small.json");
      writeFileSync(small, "{}\n");
      const symlink = join(directory, "symlink.json");
      symlinkSync(small, symlink);
      expect(run(symlink).status).toBe(1);

      const fifo = join(directory, "manifest.fifo");
      expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
      const fifoResult = run(fifo);
      expect(fifoResult.signal).toBeNull();
      expect(fifoResult.status).toBe(1);
      expect(fifoResult.stderr).toContain("not a regular file");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
