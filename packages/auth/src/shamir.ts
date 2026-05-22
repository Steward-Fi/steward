/**
 * Shamir Secret Sharing over GF(2^8) — threshold recovery for any byte-array
 * secret (private keys, vault master passwords, mnemonic-derived seeds).
 *
 * Split a secret into N shares with threshold k (1 ≤ k ≤ N ≤ 255). Any k
 * shares reconstruct the secret exactly; any k-1 shares yield zero
 * information about it (information-theoretic security in the GF(2^8)
 * polynomial evaluation, conditional on a strong RNG for coefficients).
 *
 * This is the cryptographic primitive that "social recovery" / guardian
 * schemes are built on. The recovery UX (who holds shares, when they're
 * pieced back together, how they're transmitted) is a product decision
 * layered above this module — Shamir itself just guarantees the math.
 *
 * Wire format per share: byte 0 = x-coordinate (1..255), bytes 1.. = y bytes
 * for each byte of the secret. Encoded as hex for transport. The threshold
 * is intentionally NOT in the share — callers must communicate it out of
 * band (or layer it on with a versioned envelope) so the share itself
 * doesn't leak the recovery policy.
 *
 * GF(2^8) arithmetic uses the AES polynomial (0x11b). Exponent/log tables
 * are computed once at module load.
 */

const PRIM = 0x11b; // x^8 + x^4 + x^3 + x + 1
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function buildTables() {
  // Primitive element under the AES polynomial is 3 (= x+1), NOT 2 (= x).
  // Iteratively multiply by 3 to walk the cyclic multiplicative group.
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // Multiply x by 3 in GF(2^8): (x*2) XOR x, with reduction by PRIM on overflow.
    const doubled = x << 1;
    const reduced = doubled & 0x100 ? doubled ^ PRIM : doubled;
    x = reduced ^ EXP[i]; // = 2*x XOR x = 3*x
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a: number, b: number): number {
  if (a === 0) return 0;
  if (b === 0) throw new Error("gfDiv: division by zero");
  return EXP[LOG[a] + 255 - LOG[b]];
}

/** Evaluate polynomial whose coefficients are coeffs[0]=secret, coeffs[i]=random, at x. */
function evalPoly(coeffs: Uint8Array, x: number): number {
  // Horner's rule, top-down so the LSB of `coeffs` is the constant term.
  let acc = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    acc = gfMul(acc, x) ^ coeffs[i];
  }
  return acc;
}

export interface SplitOptions {
  /** Optional deterministic RNG for tests. MUST NOT be set in production. */
  random?: (n: number) => Uint8Array;
}

/**
 * Split `secret` into `shares` shares, any `threshold` of which reconstruct it.
 * Returns an array of hex-encoded shares. The order of returned shares is
 * stable but callers should treat them as an unordered set.
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  shares: number,
  options: SplitOptions = {},
): string[] {
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > 255) {
    throw new Error("threshold must be an integer in [2, 255]");
  }
  if (!Number.isInteger(shares) || shares < threshold || shares > 255) {
    throw new Error("shares must be an integer in [threshold, 255]");
  }
  if (secret.length === 0) {
    throw new Error("secret must be non-empty");
  }

  const random =
    options.random ??
    ((n: number) => {
      const buf = new Uint8Array(n);
      crypto.getRandomValues(buf);
      return buf;
    });

  // Per-byte independent polynomial: constant term is the secret byte; the
  // other (threshold-1) coefficients are uniform random in GF(2^8).
  const out: number[][] = [];
  for (let x = 1; x <= shares; x++) {
    out.push([x]);
  }

  for (let i = 0; i < secret.length; i++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[i];
    const r = random(threshold - 1);
    for (let j = 1; j < threshold; j++) coeffs[j] = r[j - 1];
    for (let s = 0; s < shares; s++) {
      out[s].push(evalPoly(coeffs, out[s][0]));
    }
  }

  return out.map((bytes) =>
    bytes.map((b) => b.toString(16).padStart(2, "0")).join(""),
  );
}

function parseShare(hex: string): { x: number; y: Uint8Array } {
  if (typeof hex !== "string" || hex.length < 4 || hex.length % 2 !== 0) {
    throw new Error("share: invalid hex length");
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("share: non-hex characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  if (bytes[0] === 0) throw new Error("share: x-coordinate cannot be zero");
  return { x: bytes[0], y: bytes.subarray(1) };
}

/**
 * Reconstruct the secret from at least `threshold` shares (the threshold is
 * supplied at call time, not embedded in each share — see file header). All
 * shares MUST have been produced from the same split, with the same secret
 * length. Duplicate x-coordinates are rejected.
 */
export function combineShares(hexShares: string[]): Uint8Array {
  if (!Array.isArray(hexShares) || hexShares.length < 2) {
    throw new Error("combineShares: at least 2 shares are required");
  }
  const parsed = hexShares.map(parseShare);
  const xs = parsed.map((p) => p.x);
  if (new Set(xs).size !== xs.length) {
    throw new Error("combineShares: duplicate x-coordinates");
  }
  const len = parsed[0].y.length;
  for (const p of parsed) {
    if (p.y.length !== len) {
      throw new Error("combineShares: shares are different lengths");
    }
  }

  const secret = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    // Lagrange interpolation at x=0 over GF(2^8).
    let acc = 0;
    for (let j = 0; j < parsed.length; j++) {
      let num = 1;
      let den = 1;
      for (let m = 0; m < parsed.length; m++) {
        if (m === j) continue;
        num = gfMul(num, parsed[m].x); // (0 - x_m) === x_m in GF(2^8)
        den = gfMul(den, parsed[j].x ^ parsed[m].x);
      }
      acc ^= gfMul(parsed[j].y[i], gfDiv(num, den));
    }
    secret[i] = acc;
  }
  return secret;
}
