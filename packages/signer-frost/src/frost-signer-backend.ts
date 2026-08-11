/**
 * FrostSignerBackend — a {@link SignerBackend} implementation backed by N
 * `frost-signer` Rust sidecars (ZF frost-secp256k1), 2-of-3 in the prototype.
 *
 * PROTOTYPE. Dev/dummy keys only. Keygen is trusted-dealer (run once by the
 * `frost-signer keygen` command); the interface is DKG-ready but the prototype
 * does not run DKG. The defining property holds: `canReturnRawKey: false` and
 * there is no code path that assembles or exports a private key — the TS side
 * only ever handles PUBLIC round1 commitments, the signing package, public
 * signature shares, and the final signature.
 *
 * Topology: each share is a separate localhost process (stand-in for a separate
 * enclave — see THRESHOLD-SIGNING.md). The backend is constructed with the
 * share endpoints + the group public key produced by keygen.
 */

import type {
  SignerBackend,
  SignerBackendCapabilities,
  ThresholdGenerateParams,
  ThresholdKeyRef,
  ThresholdSignature,
} from "@stwd/vault";

import { ShareClient } from "./sidecar-client";

export interface FrostSignerBackendOptions {
  /** Base URLs of the running share sidecars, e.g. ["http://127.0.0.1:7401", ...]. */
  shareEndpoints: string[];
  /** t — shares required to sign. */
  threshold: number;
  /**
   * Group verifying key hex (33-byte compressed secp256k1), from
   * `frost-signer keygen`. In a real deployment this comes from the DKG output.
   */
  groupPublicKeyHex: string;
  /** Opaque group id / handle. Defaults to a hash-free label for the prototype. */
  groupId?: string;
}

/**
 * ZF frost-secp256k1 signature length: compressed R point (33) + scalar z (32).
 * Not 64 — that is BIP-340/Taproot x-only R (the separate frost-secp256k1-tr
 * crate). See THRESHOLD-SIGNING.md.
 */
export const FROST_SECP256K1_SIG_LEN = 65;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export class FrostSignerBackend implements SignerBackend {
  readonly id: string;
  readonly capabilities: SignerBackendCapabilities = {
    canReturnRawKey: false,
    supportsReshare: false,
  };

  private readonly shares: ShareClient[];
  private readonly threshold: number;
  private readonly participants: number;
  private readonly groupPublicKeyHex: string;
  private readonly groupId: string;

  constructor(opts: FrostSignerBackendOptions) {
    if (opts.shareEndpoints.length < opts.threshold) {
      throw new Error(
        `need at least threshold=${opts.threshold} share endpoints, got ${opts.shareEndpoints.length}`,
      );
    }
    this.shares = opts.shareEndpoints.map((u) => new ShareClient(u));
    this.threshold = opts.threshold;
    this.participants = opts.shareEndpoints.length;
    this.groupPublicKeyHex = opts.groupPublicKeyHex.replace(/^0x/, "");
    this.groupId = opts.groupId ?? `frost-secp256k1-${this.threshold}of${this.participants}`;
    this.id = `frost-secp256k1@${this.threshold}of${this.participants}`;
  }

  /**
   * The prototype uses trusted-dealer keygen performed OUT OF BAND via the
   * `frost-signer keygen` command, so `generate` returns the ref for the
   * already-generated group. A production DKG backend would run the ceremony
   * across the sidecars here. We reject if params disagree with the loaded
   * group so callers can't silently get a mismatched key.
   */
  async generate(params: ThresholdGenerateParams): Promise<ThresholdKeyRef> {
    if (params.scheme !== "frost-secp256k1") {
      throw new Error(`FrostSignerBackend only supports frost-secp256k1, got ${params.scheme}`);
    }
    if (params.threshold !== this.threshold || params.participants !== this.participants) {
      throw new Error(
        `requested ${params.threshold}-of-${params.participants} but backend is ` +
          `${this.threshold}-of-${this.participants} (prototype keygen is trusted-dealer, out of band)`,
      );
    }
    return this.keyRef();
  }

  keyRef(): ThresholdKeyRef {
    return {
      backend: this.id,
      groupId: this.groupId,
      publicKey: `0x${this.groupPublicKeyHex}`,
      scheme: "frost-secp256k1",
      threshold: this.threshold,
      participants: this.participants,
    };
  }

  /**
   * Produce a threshold signature over `message` using exactly `threshold`
   * shares. Uses the first `threshold` reachable share endpoints; a real
   * coordinator would pick a live quorum and handle failover. If fewer than
   * `threshold` shares participate, the Rust aggregation rejects — enforced by
   * the FROST crate itself, not by a hand-rolled count check.
   */
  async sign(ref: ThresholdKeyRef, message: Uint8Array): Promise<ThresholdSignature> {
    const quorum = this.shares.slice(0, ref.threshold);
    const messageHex = toHex(message);

    // Round 1: collect commitments + remember nonce ids per share.
    const commits = await Promise.all(quorum.map((s) => s.commit()));
    const commitmentsMap: Record<string, string> = {};
    for (const c of commits) commitmentsMap[c.identifierHex] = c.commitmentsHex;

    // Build the signing package (public op) on any share.
    const signingPackageHex = await quorum[0].buildSigningPackage(commitmentsMap, messageHex);

    // Round 2: each share produces its signature share.
    const signShares = await Promise.all(
      quorum.map((s, i) => s.sign(signingPackageHex, commits[i].nonceId)),
    );
    const shareMap: Record<string, string> = {};
    for (const ss of signShares) shareMap[ss.identifierHex] = ss.signatureShareHex;

    // Aggregate + verify (public op).
    const agg = await quorum[0].aggregate(signingPackageHex, shareMap);
    if (!agg.valid) throw new Error("aggregated signature failed verification against group key");

    return { signature: fromHex(agg.signatureHex) };
  }

  /**
   * Genuinely verify a provided signature against the group public key. This is
   * a public-data operation delegated to any reachable sidecar's `/verify`
   * endpoint, which runs `VerifyingKey::verify` from the ZF frost crate. It is
   * NOT vacuous: a wrong signature or a wrong message returns false. The Safe /
   * EIP-1271 path additionally verifies on-chain (see THRESHOLD-SIGNING.md).
   */
  async verify(
    _ref: ThresholdKeyRef,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    // ZF frost-secp256k1 serializes a signature as compressed R (33 bytes) ‖ z
    // (32 bytes) = 65 bytes. (Contrast Taproot/BIP-340 x-only R = 64 bytes,
    // which is frost-secp256k1-tr, a different crate.)
    if (signature.length !== FROST_SECP256K1_SIG_LEN) return false;
    return this.shares[0].verify(toHex(message), toHex(signature));
  }
}
