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

describe("Shamir secret sharing", () => {
  test("split → combine round-trips for the simple (2,3) case", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    expect(shares).toHaveLength(3);
    expect(bytesEqual(combineShares(pick(shares, [0, 1])), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(shares, [0, 2])), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(shares, [1, 2])), secret)).toBe(true);
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
      const recovered = combineShares(pick(shares, c));
      expect(bytesEqual(recovered, secret)).toBe(true);
    }
  });

  test("k-1 shares yield a secret different from the original (information loss below threshold)", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 3, 5);
    // Pick only 2 of the 3 required — combineShares is happy to interpolate
    // on the input it gets; we assert it does NOT reproduce the secret.
    const fake = combineShares(pick(shares, [0, 1]));
    expect(bytesEqual(fake, secret)).toBe(false);
  });

  test("works for 32-byte secrets (the EVM private key size)", () => {
    const secret = new Uint8Array(32);
    crypto.getRandomValues(secret);
    const shares = splitSecret(secret, 3, 5);
    const recovered = combineShares(pick(shares, [4, 1, 2]));
    expect(bytesEqual(recovered, secret)).toBe(true);
  });

  test("two splits of the same secret produce different shares (RNG freshness)", () => {
    const secret = hexToBytes(SECRET_HEX);
    const a = splitSecret(secret, 2, 3);
    const b = splitSecret(secret, 2, 3);
    expect(a[0] === b[0] && a[1] === b[1] && a[2] === b[2]).toBe(false);
    // Both still recover correctly.
    expect(bytesEqual(combineShares(pick(a, [0, 1])), secret)).toBe(true);
    expect(bytesEqual(combineShares(pick(b, [0, 1])), secret)).toBe(true);
  });

  test("rejects invalid threshold / shares parameters", () => {
    const secret = hexToBytes("aabb");
    expect(() => splitSecret(secret, 1, 3)).toThrow();
    expect(() => splitSecret(secret, 4, 3)).toThrow();
    expect(() => splitSecret(secret, 2, 256)).toThrow();
    expect(() => splitSecret(secret, 256, 256)).toThrow();
    expect(() => splitSecret(new Uint8Array(0), 2, 3)).toThrow();
  });

  test("combineShares rejects duplicate x-coordinates", () => {
    const secret = hexToBytes(SECRET_HEX);
    const shares = splitSecret(secret, 2, 3);
    expect(() => combineShares([shares[0], shares[0]])).toThrow();
  });

  test("combineShares rejects mismatched lengths", () => {
    expect(() => combineShares(["01aa", "02aabb"])).toThrow();
  });

  test("combineShares rejects garbage hex and zero-x shares", () => {
    expect(() => combineShares(["zz", "0102"])).toThrow();
    expect(() => combineShares(["0042", "00aa"])).toThrow(); // x = 0
    expect(() => combineShares(["01"])).toThrow(); // < 2 shares
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
    expect(bytesEqual(combineShares([a[0], a[2]]), secret)).toBe(true);
  });
});
