import { describe, expect, test } from "bun:test";

import { combineShares, splitSecret } from "../shamir";

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function pick<T>(arr: readonly T[], indices: number[]): T[] {
  return indices.map((i) => arr[i]);
}

const SECRET_HEX = "deadbeefcafebabe0123456789abcdef";
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** XOR the same delta into the y-byte at index `yIndex` of every share. */
function xorYByte(shares: string[], yIndex: number, delta: number): string[] {
  return shares.map((hex) => {
    const bytes = hexToBytes(hex);
    bytes[1 + yIndex] ^= delta;
    return bytesToHex(bytes);
  });
}

describe("Shamir secret sharing", () => {
  test("split → combine round-trips for the simple (2,3) case", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    expect(shares).toHaveLength(3);
    expect(bytesEqual(combineShares(pick(shares, [0, 1]), 2), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(shares, [0, 2]), 2), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(shares, [1, 2]), 2), secret)).toBe(true);
  });

  test("any k-of-n combination recovers the secret for (3,5)", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 3, 5);
    const combos: number[][] = [
      [0, 1, 2],
      [0, 1, 3],
      [0, 1, 4],
      [0, 2, 3],
      [0, 2, 4],
      [0, 3, 4],
      [1, 2, 3],
      [1, 2, 4],
      [1, 3, 4],
      [2, 3, 4],
    ];
    for (const c of combos) {
      const recovered = combineShares(pick(shares, c), 3);
      expect(bytesEqual(recovered, secret)).toBe(true);
    }
  });

  test("more than k shares still recover the secret", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 4);
    expect(bytesEqual(combineShares(shares, 2), secret)).toBe(true);
  });

  test("fewer than k shares throws instead of interpolating garbage (SEC-142)", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 3, 5);
    expect(() => combineShares(pick(shares, [0, 1]), 3)).toThrow(
      "fewer shares than the threshold",
    );
  });

  test("works for 32-byte secrets (the EVM private key size)", () => {
    const secret = new Uint8Array(32);
    crypto.getRandomValues(secret);
    const shares = splitSecret(secret, 3, 5);
    const recovered = combineShares(pick(shares, [4, 1, 2]), 3);
    expect(bytesEqual(recovered, secret)).toBe(true);
  });

  test("two splits of the same secret produce different shares (RNG freshness)", () => {
    const secret = hexToBytes(SECRET_HEX);
    const a = splitSecret(secret, 2, 3);
    const b = splitSecret(secret, 2, 3);
    expect(a[0] === b[0] && a[1] === b[1] && a[2] === b[2]).toBe(false);
    // Both still recover correctly.
    expect(bytesEqual(combineShares(pick(a, [0, 1]), 2), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(b, [0, 1]), 2), secret)).toBe(true);
  });

  test("rejects invalid threshold / shares parameters", () => {
    const secret = hexToBytes("aabb");
    expect(() => splitSecret(secret, 1, 3)).toThrow();
    expect(() => splitSecret(secret, 4, 3)).toThrow();
    expect(() => splitSecret(secret, 2, 256)).toThrow();
    expect(() => splitSecret(secret, 256, 256)).toThrow();
    expect(() => splitSecret(new Uint8Array(0), 2, 3)).toThrow();
    expect(() => splitSecret(new Uint8Array(4097), 2, 3)).toThrow();
    expect(() => combineShares(["01aa", "02bb"], 1)).toThrow();
    expect(() => combineShares(["01aa", "02bb"], 256)).toThrow();
  });

  test("combineShares rejects duplicate x-coordinates", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    expect(() => combineShares([shares[0], shares[0]], 2)).toThrow();
  });

  test("combineShares rejects mismatched lengths", () => {
    expect(() => combineShares(["01aa", "02aabb"], 2)).toThrow();
  });

  test("combineShares rejects garbage hex, zero-x, and overlong shares", () => {
    expect(() => combineShares(["zz", "0102"], 2)).toThrow();
    expect(() => combineShares(["0042", "00aa"], 2)).toThrow(); // x = 0
    expect(() => combineShares(["01"], 2)).toThrow(); // < threshold shares
    expect(() => combineShares(["01" + "ab".repeat(5000), "02" + "cd".repeat(5000)], 2)).toThrow(
      "invalid hex length",
    );
  });

  test("corrupted share fails the integrity check instead of returning a wrong secret", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    const tampered = [...shares];
    const bytes = hexToBytes(tampered[1]);
    bytes[3] ^= 0x01; // flip one payload byte
    tampered[1] = bytesToHex(bytes);
    expect(() => combineShares(pick(tampered, [0, 1]), 2)).toThrow("integrity check failed");
  });

  test("shares from different splits fail closed", () => {
    const secret = hexToBytes(SECRET_HEX);
    const a = splitSecret(secret, 2, 3);
    const b = splitSecret(secret, 2, 3);
    // Which guard fires (version byte vs checksum) depends on the random
    // reconstruction; the contract is that mixed input never yields a secret.
    expect(() => combineShares([a[0], b[1]], 2)).toThrow("combineShares:");
  });

  test("a split of a different secret fails closed when mixed", () => {
    const a = splitSecret(hexToBytes(SECRET_HEX), 2, 3);
    const b = splitSecret(hexToBytes("00112233445566778899aabbccddeeff"), 2, 3);
    expect(() => combineShares([a[0], b[1]], 2)).toThrow("combineShares:");
  });

  test("an unsupported envelope version is rejected", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    // Lagrange interpolation is linear and the basis sums to 1, so XOR-ing a
    // delta into y[0] (the version byte position) of every share XORs it into
    // the reconstructed version byte — a deterministic version mismatch.
    const wrongVersion = xorYByte(shares, 0, 0xff);
    expect(() => combineShares(pick(wrongVersion, [0, 1]), 2)).toThrow(
      "unsupported share format version",
    );
  });

  test("deterministic RNG produces deterministic shares (test ergonomics)", () => {
    const secret = hexToBytes("01020304");
    let i = 0;
    const seq = new Uint8Array([
      0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0xcc,
    ]);
    const fakeRandom = (n: number) => {
      const out = seq.subarray(i, i + n);
      i += n;
      return new Uint8Array(out);
    };
    const a = splitSecret(secret, 2, 3, { random: fakeRandom });
    i = 0;
    const b = splitSecret(secret, 2, 3, { random: fakeRandom });
    expect(a).toEqual(b);
    expect(bytesEqual(combineShares([a[0], a[2]], 2), secret)).toBe(true);
  });
});
