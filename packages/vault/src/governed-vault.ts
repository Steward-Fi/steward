import type { ExecutionAuthorization, SignRequest } from "@stwd/shared";
import type { SignTransactionOptions, Vault } from "./vault";

export type ExecutionAuthorizationConsumeCallback = (
  authorization: ExecutionAuthorization,
  expected: {
    tenantId: string;
    agentId: string;
    capability: "wallet.sign_transaction";
    backend: "local-vault";
    payloadDigest: string;
  },
) => Promise<void>;

export class GovernedVaultError extends Error {
  constructor(
    message: string,
    readonly code:
      | "missing_authorization"
      | "missing_payload_digest"
      | "unsupported_chain_family"
      | "authorization_rejected",
  ) {
    super(message);
    this.name = "GovernedVaultError";
  }
}

export interface GovernedSignTransactionOptions extends SignTransactionOptions {
  executionAuthorization?: ExecutionAuthorization;
  executionPayloadDigest?: string;
}

export class GovernedVault {
  constructor(
    private readonly rawVault: Vault,
    private readonly consumeExecutionAuthorization: ExecutionAuthorizationConsumeCallback,
  ) {}

  async signTransaction(
    request: SignRequest,
    options: GovernedSignTransactionOptions,
  ): Promise<string> {
    const chainId = request.chainId || 8453;
    if (chainId === 101 || chainId === 102) {
      throw new GovernedVaultError(
        "GovernedVault.signTransaction is scoped to the EVM transaction path",
        "unsupported_chain_family",
      );
    }
    if (!options.executionAuthorization) {
      throw new GovernedVaultError(
        "Execution authorization is required for governed EVM transaction signing",
        "missing_authorization",
      );
    }
    if (!options.executionPayloadDigest) {
      throw new GovernedVaultError(
        "Execution payload digest is required for governed EVM transaction signing",
        "missing_payload_digest",
      );
    }

    try {
      await this.consumeExecutionAuthorization(options.executionAuthorization, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        capability: "wallet.sign_transaction",
        backend: "local-vault",
        payloadDigest: options.executionPayloadDigest,
      });
    } catch (error) {
      if (error instanceof GovernedVaultError) throw error;
      const message =
        error instanceof Error ? error.message : "Execution authorization was rejected";
      throw new GovernedVaultError(message, "authorization_rejected");
    }

    const {
      executionAuthorization: _authorization,
      executionPayloadDigest: _digest,
      ...rawOptions
    } = options;
    return this.rawVault.signTransaction(request, rawOptions);
  }
}
