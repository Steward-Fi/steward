/**
 * Thin HTTP client for a single `frost-signer share` sidecar process.
 *
 * Each sidecar holds ONE FROST secret share and exposes a small localhost HTTP
 * API (see sidecar/src/main.rs). This client never sees share material — only
 * public round1 commitments, the serialized signing package, public signature
 * shares, and the final aggregated signature. That is the whole point: the TS
 * side is a coordinator over public data, all secret operations stay in the
 * audited Rust crate inside the sidecar.
 */

export interface CommitResult {
  identifierHex: string;
  nonceId: string;
  commitmentsHex: string;
}

export interface SignShareResult {
  identifierHex: string;
  signatureShareHex: string;
}

export interface AggregateResult {
  signatureHex: string;
  groupPublicKeyHex: string;
  valid: boolean;
}

async function postJson(url: string, body: unknown, authToken?: string): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // SEC-025: the share sidecar requires a per-share bearer token.
      ...(authToken ? { authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`sidecar ${url} returned non-JSON (status ${res.status}): ${text}`);
  }
  if (
    !res.ok ||
    (typeof parsed === "object" && parsed !== null && (parsed as { ok?: boolean }).ok === false)
  ) {
    const msg =
      (typeof parsed === "object" && parsed !== null && (parsed as { error?: string }).error) ||
      `status ${res.status}`;
    throw new Error(`sidecar ${url} error: ${msg}`);
  }
  return parsed;
}

/** A handle to one running share sidecar, addressed by localhost port. */
export class ShareClient {
  constructor(
    private readonly baseUrl: string,
    private readonly authToken?: string,
  ) {}

  async health(): Promise<{ id: string }> {
    const res = await fetch(`${this.baseUrl}/health`);
    const j = (await res.json()) as { id: string; ok: boolean };
    if (!j.ok) throw new Error(`share ${this.baseUrl} unhealthy`);
    return { id: j.id };
  }

  /** Round 1: this share generates single-use nonces + public commitments. */
  async commit(): Promise<CommitResult> {
    const j = (await postJson(`${this.baseUrl}/commit`, {}, this.authToken)) as {
      identifier_hex: string;
      nonce_id: string;
      commitments_hex: string;
    };
    return {
      identifierHex: j.identifier_hex,
      nonceId: j.nonce_id,
      commitmentsHex: j.commitments_hex,
    };
  }

  /** Build a SigningPackage from public commitments + message (public op). */
  async buildSigningPackage(
    commitments: Record<string, string>,
    messageHex: string,
  ): Promise<string> {
    const j = (await postJson(
      `${this.baseUrl}/signing-package`,
      {
        commitments,
        message_hex: messageHex,
      },
      this.authToken,
    )) as { signing_package_hex: string };
    return j.signing_package_hex;
  }

  /** Round 2: this share produces its signature share for the signing package. */
  async sign(signingPackageHex: string, nonceId: string): Promise<SignShareResult> {
    const j = (await postJson(
      `${this.baseUrl}/sign`,
      {
        signing_package_hex: signingPackageHex,
        nonce_id: nonceId,
      },
      this.authToken,
    )) as { identifier_hex: string; signature_share_hex: string };
    return { identifierHex: j.identifier_hex, signatureShareHex: j.signature_share_hex };
  }

  /** Genuinely verify a provided signature against this group's key (public op). */
  async verify(messageHex: string, signatureHex: string): Promise<boolean> {
    const j = (await postJson(
      `${this.baseUrl}/verify`,
      {
        message_hex: messageHex,
        signature_hex: signatureHex,
      },
      this.authToken,
    )) as { valid: boolean };
    return j.valid;
  }

  /** Aggregate signature shares into the group signature (public op + verify). */
  async aggregate(
    signingPackageHex: string,
    signatureShares: Record<string, string>,
  ): Promise<AggregateResult> {
    const j = (await postJson(
      `${this.baseUrl}/aggregate`,
      {
        signing_package_hex: signingPackageHex,
        signature_shares: signatureShares,
      },
      this.authToken,
    )) as { signature_hex: string; group_public_key_hex: string; valid: boolean };
    return {
      signatureHex: j.signature_hex,
      groupPublicKeyHex: j.group_public_key_hex,
      valid: j.valid,
    };
  }
}
