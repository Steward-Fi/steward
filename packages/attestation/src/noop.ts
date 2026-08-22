import { runtimeEnvironmentSnapshot } from "@stwd/shared/runtime-env";
import type {
  AttestationProvider,
  AttestationQuote,
  AttestationQuoteRequest,
  AttestationVerificationOptions,
} from "./types.js";

export interface NoopDevProviderOptions {
  allowUnverified?: boolean;
  /**
   * Dual consent for the insecure dev escape hatch, mirroring the repo-wide
   * STEWARD_ALLOW_DEV_SECRETS convention. Defaults to the env var.
   */
  allowDevSecrets?: boolean;
  environment?: string;
  now?: () => Date;
}

export class NoopDevAttestationProvider implements AttestationProvider {
  readonly id = "noop-dev" as const;
  private readonly allowUnverified: boolean;
  private readonly environment: string;
  private readonly now: () => Date;

  constructor(options: NoopDevProviderOptions = {}) {
    const env = runtimeEnvironmentSnapshot();
    const requested = options.allowUnverified ?? env.STEWARD_ATTESTATION_NOOP_ALLOW === "true";
    this.environment =
      options.environment ??
      env.NODE_ENV ??
      (env.STEWARD_RUNTIME === "workers" ? "production" : "development");
    this.now = options.now ?? (() => new Date());
    // SEC-029: keying the insecure mode solely on NODE_ENV means any
    // deployment that forgets NODE_ENV=production gets vacuous-green quotes.
    // Require dual consent like every other dev escape hatch in this repo:
    // STEWARD_ATTESTATION_NOOP_ALLOW=true AND STEWARD_ALLOW_DEV_SECRETS=true,
    // and never in production.
    const devSecretsAllowed =
      options.allowDevSecrets ??
      (env.STEWARD_ALLOW_DEV_SECRETS === "true" || env.STEWARD_ALLOW_DEV_SECRET === "true");
    if (requested && this.environment === "production") {
      throw new Error("noop-dev attestation cannot be explicitly allowed in production");
    }
    if (requested && !devSecretsAllowed) {
      throw new Error(
        "noop-dev attestation requires dual consent: set STEWARD_ALLOW_DEV_SECRETS=true " +
          "alongside STEWARD_ATTESTATION_NOOP_ALLOW=true (local development only; never set " +
          "these in a shared or production environment)",
      );
    }
    this.allowUnverified = requested;
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
