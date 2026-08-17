import { describe, expect, test } from "bun:test";
import { assertSafeArchiveChunks, assertSafeArchiveManifestTransport } from "../index";

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
});
