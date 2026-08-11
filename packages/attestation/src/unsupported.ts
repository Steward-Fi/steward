import type { AttestationProvider, AttestationQuote, UnsupportedProviderOptions } from "./types.js";

export class UnsupportedAttestationProvider implements AttestationProvider {
  readonly id: UnsupportedProviderOptions["provider"];

  constructor(options: UnsupportedProviderOptions) {
    this.id = options.provider;
  }

  async generateQuote(): Promise<AttestationQuote> {
    throw new Error(
      `${this.id} attestation provider is an interface seam only; no implementation is wired yet`,
    );
  }

  async verifyQuote(): Promise<AttestationQuote> {
    throw new Error(
      `${this.id} attestation provider is an interface seam only; no implementation is wired yet`,
    );
  }
}
