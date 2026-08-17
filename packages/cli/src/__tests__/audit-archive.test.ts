import { describe, expect, test } from "bun:test";
import { assertSafeArchiveChunks } from "../index";

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
});
