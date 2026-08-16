import type {
  AttestationProvider,
  AttestationQuote,
  AttestationQuoteRequest,
  AttestationVerificationOptions,
} from "./types.js";

export interface NoopDevProviderOptions {
  allowUnverified?: boolean;
  environment?: string;
  now?: () => Date;
}

export class NoopDevAttestationProvider implements AttestationProvider {
  readonly id = "noop-dev" as const;
  private readonly allowUnverified: boolean;
  private readonly environment: string;
  private readonly now: () => Date;

  constructor(options: NoopDevProviderOptions = {}) {
    this.allowUnverified =
      options.allowUnverified ?? process.env.STEWARD_ATTESTATION_NOOP_ALLOW === "true";
    this.environment = options.environment ?? process.env.NODE_ENV ?? "development";
    this.now = options.now ?? (() => new Date());
    if (this.allowUnverified && this.environment === "production") {
      throw new Error("noop-dev attestation cannot be explicitly allowed in production");
    }
  }

  async generateQuote(request: AttestationQuoteRequest = {}): Promise<AttestationQuote> {
    return this.result({ request });
  }

  async verifyQuote(
    rawQuote: unknown,
    options: AttestationVerificationOptions = {},
  ): Promise<AttestationQuote> {
    return this.result({ rawQuote, options });
  }

  private result(raw: unknown): AttestationQuote {
    return {
      provider: this.id,
      measurement: { imageDigest: "noop-dev", configHash: "noop-dev" },
      timestamp: this.now().toISOString(),
      verified: this.allowUnverified,
      raw: {
        raw,
        warning: this.allowUnverified
          ? "noop-dev explicitly allowed for local development only"
          : "noop-dev never proves hardware isolation; set STEWARD_ATTESTATION_NOOP_ALLOW=true only for local development",
      },
    };
  }
}

export function createNoopDevProvider(
  options?: NoopDevProviderOptions,
): NoopDevAttestationProvider {
  return new NoopDevAttestationProvider(options);
}
