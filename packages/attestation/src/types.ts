export type AttestationProviderId = "dstack-tdx" | "noop-dev" | "aws-nitro" | "amd-sev-snp";

export interface AttestationMeasurement {
  /**
   * Runtime image identity. For dstack this is the verified dstack OS image hash;
   * application container image digests are bound through configHash/compose_hash
   * when the compose file pins images by digest.
   */
  imageDigest: string;
  /** Runtime configuration identity. For dstack this is compose_hash. */
  configHash: string;
}

export interface AttestationQuoteRequest {
  /** Caller challenge, encoded as UTF-8 or hex depending on provider options. */
  nonce?: string;
  /** Optional deployment target for registry checks (for example: phala-prod). */
  deployment?: string;
}

export interface AttestationQuote {
  provider: AttestationProviderId;
  measurement: AttestationMeasurement;
  timestamp: string;
  /** True only after hardware/root verification and provider policy checks pass. */
  verified: boolean;
  raw: unknown;
}

export interface AttestationVerificationOptions {
  nonce?: string;
  now?: Date;
}

export interface AttestationProvider {
  readonly id: AttestationProviderId;
  /** Server-side quote/evidence generation. */
  generateQuote(request?: AttestationQuoteRequest): Promise<AttestationQuote>;
  /** Client-side quote/evidence verification. */
  verifyQuote(
    rawQuote: unknown,
    options?: AttestationVerificationOptions,
  ): Promise<AttestationQuote>;
}

export interface UnsupportedProviderOptions {
  provider: Exclude<AttestationProviderId, "dstack-tdx" | "noop-dev">;
}
