import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertSafeArchiveChunks,
  assertSafeArchiveManifestTransport,
  readBoundedRegularFile,
} from "../index";

describe("audit archive filesystem boundaries", () => {
  test("accepts only canonical, sequential chunk basenames", () => {
    expect(() =>
      assertSafeArchiveChunks(
        [
          {
            index: 0,
            file: "chunk-000000.jsonl",
            sha256: "a".repeat(64),
            byteLength: 10,
          },
        ],
        true,
      ),
    ).not.toThrow();

    for (const chunks of [
      [{ index: 0, file: "../../.ssh/authorized_keys" }],
      [{ index: 1, file: "chunk-000001.jsonl" }],
      [{ index: 0, file: "/tmp/chunk-000000.jsonl" }],
      [{ index: 0, file: "chunk-000000.jsonl", sha256: "bad", byteLength: 10 }],
      [{ index: 0, file: "chunk-000000.jsonl", sha256: "a".repeat(64), byteLength: 0 }],
    ]) {
      expect(() => assertSafeArchiveChunks(chunks, true)).toThrow("invalid or unsafe");
    }
  });

  test("keeps the maximum legal one-event chunk manifest transportable", () => {
    const chunks = Array.from({ length: 2_048 }, (_, index) => ({
      index,
      file: `chunk-${String(index).padStart(6, "0")}.jsonl`,
      sha256: "a".repeat(64),
      byteLength: 1,
    }));
    expect(() => assertSafeArchiveChunks(chunks, true)).not.toThrow();
    expect(() => assertSafeArchiveManifestTransport({ chunks })).not.toThrow();
    expect(new TextEncoder().encode(JSON.stringify({ chunks })).length).toBeLessThan(768 * 1024);

    expect(() =>
      assertSafeArchiveChunks([
        ...chunks,
        {
          index: 2_048,
          file: "chunk-002048.jsonl",
          sha256: "a".repeat(64),
          byteLength: 1,
        },
      ]),
    ).toThrow("invalid chunk list");
    expect(() =>
      assertSafeArchiveManifestTransport({ chunks, padding: "x".repeat(768 * 1024) }),
    ).toThrow("safe API transport limit");
  });

  test("bounded reads reject oversized, symlink, and FIFO archive inputs without blocking", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-archive-input-"));
    try {
      const regular = join(directory, "regular.jsonl");
      writeFileSync(regular, "safe\n");
      expect(readBoundedRegularFile(regular, 5, 5).toString("utf8")).toBe("safe\n");

      const oversized = join(directory, "oversized.jsonl");
      writeFileSync(oversized, Buffer.alloc(17));
      expect(() => readBoundedRegularFile(oversized, 16)).toThrow("16 byte limit");

      const symlink = join(directory, "symlink.jsonl");
      symlinkSync(regular, symlink);
      expect(() => readBoundedRegularFile(symlink, 16)).toThrow();

      const fifo = join(directory, "fifo.jsonl");
      const made = spawnSync("mkfifo", [fifo]);
      expect(made.status).toBe(0);
      expect(() => readBoundedRegularFile(fifo, 16)).toThrow("not a regular file");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
