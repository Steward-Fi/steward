/**
 * E2E FROST-secp256k1 2-of-3 threshold-signing test.
 *
 * Bidirectional proof (D2 requirement):
 *   POSITIVE: 3 real share processes, 2 of them produce a signature that
 *             cryptographically verifies against the group public key.
 *   NEGATIVE: 1 of 3 shares CANNOT produce a valid signature — the below-
 *             threshold case must actually fail (enforced by the ZF frost crate,
 *             not by a hand-rolled count check).
 *   TAMPER:   verify() rejects a mutated signature / wrong message.
 *
 * These run against three real `frost-signer` sidecar processes (stand-ins for
 * three separate enclaves). Dev/dummy keys only, generated per run.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { FrostSignerBackend } from "../frost-signer-backend";
import { ShareClient } from "../sidecar-client";
import { type FrostCluster, readGroupFile, startFrostCluster } from "./harness";

let cluster: FrostCluster;
let backend: FrostSignerBackend;

beforeAll(async () => {
  cluster = await startFrostCluster(2, 3);
  backend = new FrostSignerBackend({
    shareEndpoints: cluster.endpoints,
    threshold: cluster.threshold,
    groupPublicKeyHex: cluster.groupPublicKeyHex,
  });
});

afterAll(() => {
  cluster?.teardown();
});

function digest(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe("FROST-secp256k1 2-of-3 threshold signing (E2E, real sidecars)", () => {
  test("backend advertises canReturnRawKey: false and no raw-key path", () => {
    expect(backend.capabilities.canReturnRawKey).toBe(false);
    expect((backend as Record<string, unknown>).exportPrivateKey).toBeUndefined();
    expect((backend as Record<string, unknown>).decrypt).toBeUndefined();
  });

  test("keygen produced a 33-byte compressed group public key", () => {
    const g = readGroupFile(cluster.shareDir);
    expect(g.threshold).toBe(2);
    expect(g.participants).toBe(3);
    // 33 bytes = 66 hex chars, compressed SEC1 point (0x02/0x03 prefix).
    expect(g.group_public_key_hex).toHaveLength(66);
    expect(["02", "03"]).toContain(g.group_public_key_hex.slice(0, 2));
    expect(g.group_public_key_hex).toBe(cluster.groupPublicKeyHex);
  });

  test("generate() returns a ThresholdKeyRef with the group key, no secret", async () => {
    const ref = await backend.generate({
      scheme: "frost-secp256k1",
      threshold: 2,
      participants: 3,
    });
    expect(ref.scheme).toBe("frost-secp256k1");
    expect(ref.threshold).toBe(2);
    expect(ref.publicKey).toBe(`0x${cluster.groupPublicKeyHex}`);
    expect(JSON.stringify(ref).toLowerCase()).not.toContain("private");
    expect(JSON.stringify(ref).toLowerCase()).not.toContain("secret");
  });

  test("POSITIVE: 2 of 3 shares produce a signature that verifies", async () => {
    const ref = backend.keyRef();
    const msg = digest(0x11);
    const sig = await backend.sign(ref, msg);

    // ZF frost-secp256k1 signature is 65 bytes: compressed R (33) ‖ z (32).
    expect(sig.signature.length).toBe(65);

    // Cryptographic verification against the group key (real, via sidecar).
    const ok = await backend.verify(ref, msg, sig.signature);
    expect(ok).toBe(true);
  });

  test("POSITIVE: signing is repeatable for different messages", async () => {
    const ref = backend.keyRef();
    const a = await backend.sign(ref, digest(0x22));
    const b = await backend.sign(ref, digest(0x33));
    expect(await backend.verify(ref, digest(0x22), a.signature)).toBe(true);
    expect(await backend.verify(ref, digest(0x33), b.signature)).toBe(true);
    // A signature over message A must NOT verify as message B (no vacuous pass).
    expect(await backend.verify(ref, digest(0x33), a.signature)).toBe(false);
  });

  test("NEGATIVE: 1 of 3 shares CANNOT produce a valid signature", async () => {
    // Drive the protocol by hand with a SINGLE share against a 2-of-3 group.
    const only = new ShareClient(cluster.endpoints[0]);
    const msg = digest(0x44);
    const msgHex = Array.from(msg, (b) => b.toString(16).padStart(2, "0")).join("");

    const c = await only.commit();
    const spHex = await only.buildSigningPackage({ [c.identifierHex]: c.commitmentsHex }, msgHex);

    // The ZF frost crate rejects round2 signing with too few commitments for a
    // 2-of-3 group. This MUST throw — proving 1 share cannot sign.
    await expect(only.sign(spHex, c.nonceId)).rejects.toThrow();
  });

  test("NEGATIVE: a lone valid signature share cannot be aggregated to threshold", async () => {
    // Even if an attacker obtains ONE well-formed signature share (simulated by
    // building a 2-party signing package but only submitting one share to
    // aggregate), aggregation to a valid group signature must fail.
    const s0 = new ShareClient(cluster.endpoints[0]);
    const s1 = new ShareClient(cluster.endpoints[1]);
    const msg = digest(0x55);
    const msgHex = Array.from(msg, (b) => b.toString(16).padStart(2, "0")).join("");

    const c0 = await s0.commit();
    const c1 = await s1.commit();
    const spHex = await s0.buildSigningPackage(
      { [c0.identifierHex]: c0.commitmentsHex, [c1.identifierHex]: c1.commitmentsHex },
      msgHex,
    );
    const ss0 = await s0.sign(spHex, c0.nonceId);

    // Only ONE signature share submitted -> aggregation must reject.
    await expect(
      s0.aggregate(spHex, { [ss0.identifierHex]: ss0.signatureShareHex }),
    ).rejects.toThrow();
  });

  test("TAMPER: verify() rejects a mutated signature", async () => {
    const ref = backend.keyRef();
    const msg = digest(0x66);
    const sig = await backend.sign(ref, msg);
    expect(await backend.verify(ref, msg, sig.signature)).toBe(true);

    const mutated = Uint8Array.from(sig.signature);
    mutated[10] ^= 0xff;
    expect(await backend.verify(ref, msg, mutated)).toBe(false);
  });

  test("EIP-1271 / Safe path: signature shape is what an EIP-1271 verifier expects (documented)", async () => {
    // What is PROVEN here: the signature is a 64-byte secp256k1 Schnorr sig
    // (R‖z) verifying against the 33-byte compressed group key. This is exactly
    // the (pubkey, sig) pair a safe-research/safe-frost EIP-1271 verifier
    // consumes on-chain. What is NOT proven here (documented in
    // THRESHOLD-SIGNING.md): an actual on-chain Safe deployment + isValidSignature
    // call. This unit assertion nails the FORMAT contract only.
    const ref = backend.keyRef();
    const sig = await backend.sign(ref, digest(0x77));
    expect(sig.signature.length).toBe(65); // compressed R (33) ‖ z (32)
    expect(cluster.groupPublicKeyHex.length).toBe(66); // 33-byte compressed pubkey
    expect(sig.recid).toBeUndefined(); // Schnorr has no ECDSA recovery id
  });
});
