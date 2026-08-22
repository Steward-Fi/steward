import { createHash } from "node:crypto";
import {
  canonicalJsonStringify,
  type ExecutionAuthorization,
  normalizeEvmExecutionPayload,
  type SignRequest,
  type SignSolanaTransactionRequest,
} from "@stwd/shared";
import { createGovernedParsedSolanaSigningGrant } from "./governed-solana-signing";
import { normalizedSolanaMessageDigest } from "./solana";
import type { SignTransactionOptions, Vault } from "./vault";

export type ExecutionAuthorizationConsumeCallback = (
  authorization: ExecutionAuthorization,
  expected: {
    tenantId: string;
    agentId: string;
    capability: "wallet.sign_transaction";
    backend: "local-vault" | "external-custody";
    backendIdentityDigest?: string;
    payloadDigest: string;
  },
) => Promise<void>;

export class GovernedVaultError extends Error {
  constructor(
    message: string,
    readonly code:
      | "missing_authorization"
      | "missing_payload_digest"
      | "payload_digest_mismatch"
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

export interface GovernedSolanaNativeSignOptions extends SignTransactionOptions {
  executionToken: string;
  executionClaimDigest: string;
  executionPayloadDigest: string;
  consumeExecutionClaim: (expected: {
    tenantId: string;
    agentId: string;
    txId: string;
    executionToken: string;
    executionClaimDigest: string;
    payloadDigest: string;
  }) => Promise<void>;
}

export interface GovernedSolanaParsedEffects {
  movesNativeSol: boolean;
  programIds: string[];
  tokenTransfers: Array<{ mint?: string; destination: string; amount: string }>;
}

export type GovernedSolanaParsedSignRequest = Omit<
  SignSolanaTransactionRequest,
  "allowBlindSign" | "expectedTo" | "expectedValue"
> & {
  allowBlindSign?: never;
  expectedTo?: never;
  expectedValue?: never;
};

export interface GovernedSolanaParsedExecutionClaim {
  tenantId: string;
  agentId: string;
  txId: string;
  executionToken: string;
  executionClaimDigest: string;
  executionPayloadDigest: string;
  messageDigest: string;
  parsedEffects: GovernedSolanaParsedEffects;
  policyRevisionHash: string;
  chainId: number;
  broadcast: boolean;
}

export interface GovernedSolanaParsedSignOptions {
  txId: string;
  executionToken: string;
  executionClaimDigest: string;
  executionPayloadDigest: string;
  messageDigest: string;
  parsedEffects: GovernedSolanaParsedEffects;
  policyRevisionHash: string;
  consumeExecutionClaim: (expected: GovernedSolanaParsedExecutionClaim) => Promise<void>;
}

export function executionPayloadDigestForGovernedSolanaParsedSign(
  request: GovernedSolanaParsedSignRequest,
  input: {
    messageDigest: string;
    parsedEffects: GovernedSolanaParsedEffects;
    policyRevisionHash: string;
  },
): string {
  const chainId = request.chainId ?? 101;
  if (chainId !== 101 && chainId !== 102) {
    throw new GovernedVaultError(
      "Governed parsed Solana signing requires a Solana chain",
      "unsupported_chain_family",
    );
  }
  const actualMessageDigest = normalizedSolanaMessageDigest(request.transaction);
  if (!input.messageDigest || input.messageDigest !== actualMessageDigest) {
    throw new GovernedVaultError(
      "Parsed Solana message digest does not match the serialized transaction",
      "payload_digest_mismatch",
    );
  }
  if (!input.policyRevisionHash) {
    throw new GovernedVaultError(
      "Parsed Solana signing requires a policy revision",
      "missing_authorization",
    );
  }
  return createHash("sha256")
    .update(
      canonicalJsonStringify({
        agentId: request.agentId,
        broadcast: request.broadcast !== false,
        chainId,
        messageDigest: actualMessageDigest,
        parsedEffects: input.parsedEffects,
        policyRevisionHash: input.policyRevisionHash,
        tenantId: request.tenantId,
      }),
    )
    .digest("hex");
}

export function executionClaimDigestForGovernedSolanaParsedSign(input: {
  executionPayloadDigest: string;
  executionToken: string;
  txId: string;
}): string {
  return createHash("sha256")
    .update(
      canonicalJsonStringify({
        executionPayloadDigest: input.executionPayloadDigest,
        executionToken: input.executionToken,
        txId: input.txId,
      }),
    )
    .digest("hex");
}

export function executionPayloadDigestForGovernedSolanaNativeSign(request: SignRequest): string {
  const chainId = request.chainId ?? 101;
  if (chainId !== 101 && chainId !== 102) {
    throw new GovernedVaultError(
      "Governed Solana native signing requires a Solana chain",
      "unsupported_chain_family",
    );
  }
  return createHash("sha256")
    .update(
      canonicalJsonStringify({
        agentId: request.agentId,
        broadcast: request.broadcast !== false,
        chainId,
        data: request.data ?? null,
        tenantId: request.tenantId,
        to: request.to,
        value: request.value,
      }),
    )
    .digest("hex");
}

/**
 * Digest binds the normalized transaction INTENT (caller-controlled,
 * policy-relevant fields) via the SINGLE shared canonicalizer/normalizer in
 * @stwd/shared. It does NOT bind the node-resolved final serialized envelope;
 * nonce/gas price may still be finalized inside the raw Vault after the
 * authorization is consumed. The normalizer validates chainId/nonce as
 * non-negative safe integers and throws on malformed caller fields so a bad
 * request can never be digested past this boundary.
 */
export function executionPayloadDigestForGovernedEvmSign(request: SignRequest): string {
  return createHash("sha256")
    .update(canonicalJsonStringify(normalizeEvmExecutionPayload(request)))
    .digest("hex");
}

export class GovernedVault {
  constructor(
    private readonly rawVault: Vault,
    private readonly consumeExecutionAuthorization: ExecutionAuthorizationConsumeCallback,
  ) {}

  async signTransactionAuthorized(
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
    const requestPayloadDigest = executionPayloadDigestForGovernedEvmSign(request);
    if (options.executionPayloadDigest !== requestPayloadDigest) {
      throw new GovernedVaultError(
        "Execution payload digest does not match governed EVM transaction request",
        "payload_digest_mismatch",
      );
    }

    try {
      const backend = options.executionAuthorization.backend;
      if (backend !== "local-vault" && backend !== "external-custody") {
        throw new GovernedVaultError("Unsupported custody backend", "authorization_rejected");
      }
      await this.consumeExecutionAuthorization(options.executionAuthorization, {
        tenantId: request.tenantId,
        agentId: request.agentId,
        capability: "wallet.sign_transaction",
        backend,
        backendIdentityDigest: options.executionAuthorization.backendIdentityDigest,
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
    // Bind the raw signer to the SAME custody backend this governed
    // authorization was consumed against. The raw vault
    // re-resolves the backend from the fresh wallet lookup it will sign with
    // and fails closed (BackendBindingMismatchError) if the wallet has flipped
    // to third-party custody since resolveExecutionBackend ran, closing the
    // resolution->sign TOCTOU before any external provider is reached.
    return this.rawVault.signTransaction(request, {
      ...rawOptions,
      expectedBackend: options.executionAuthorization.backend as "local-vault" | "external-custody",
      expectedBackendIdentityDigest: options.executionAuthorization.backendIdentityDigest,
    });
  }

  async signSolanaNativeTransferAuthorized(
    request: SignRequest,
    options: GovernedSolanaNativeSignOptions,
  ): Promise<string> {
    if (!options.txId || !options.executionToken || !options.executionClaimDigest) {
      throw new GovernedVaultError(
        "A durable Solana execution claim is required",
        "missing_authorization",
      );
    }
    const payloadDigest = executionPayloadDigestForGovernedSolanaNativeSign(request);
    if (!options.executionPayloadDigest || options.executionPayloadDigest !== payloadDigest) {
      throw new GovernedVaultError(
        "Solana execution payload digest does not match the governed request",
        "payload_digest_mismatch",
      );
    }
    try {
      await options.consumeExecutionClaim({
        tenantId: request.tenantId,
        agentId: request.agentId,
        txId: options.txId,
        executionToken: options.executionToken,
        executionClaimDigest: options.executionClaimDigest,
        payloadDigest,
      });
    } catch (error) {
      if (error instanceof GovernedVaultError) throw error;
      throw new GovernedVaultError(
        error instanceof Error ? error.message : "Solana execution claim was rejected",
        "authorization_rejected",
      );
    }

    const {
      consumeExecutionClaim: _consume,
      executionClaimDigest: _claimDigest,
      executionPayloadDigest: _payloadDigest,
      executionToken: _token,
      ...rawOptions
    } = options;
    return this.rawVault.signTransaction(request, rawOptions);
  }

  async signSolanaParsedTransactionAuthorized(
    request: GovernedSolanaParsedSignRequest,
    options: GovernedSolanaParsedSignOptions,
  ): ReturnType<Vault["signSolanaTransaction"]> {
    if (!options.txId || !options.executionToken || !options.executionClaimDigest) {
      throw new GovernedVaultError(
        "A durable parsed Solana execution claim is required",
        "missing_authorization",
      );
    }
    const executionPayloadDigest = executionPayloadDigestForGovernedSolanaParsedSign(request, {
      messageDigest: options.messageDigest,
      parsedEffects: options.parsedEffects,
      policyRevisionHash: options.policyRevisionHash,
    });
    if (
      !options.executionPayloadDigest ||
      options.executionPayloadDigest !== executionPayloadDigest ||
      options.executionClaimDigest !==
        executionClaimDigestForGovernedSolanaParsedSign({
          executionPayloadDigest,
          executionToken: options.executionToken,
          txId: options.txId,
        })
    ) {
      throw new GovernedVaultError(
        "Parsed Solana execution digest does not match the governed request",
        "payload_digest_mismatch",
      );
    }

    const expected: GovernedSolanaParsedExecutionClaim = {
      tenantId: request.tenantId,
      agentId: request.agentId,
      txId: options.txId,
      executionToken: options.executionToken,
      executionClaimDigest: options.executionClaimDigest,
      executionPayloadDigest,
      messageDigest: options.messageDigest,
      parsedEffects: options.parsedEffects,
      policyRevisionHash: options.policyRevisionHash,
      chainId: request.chainId ?? 101,
      broadcast: request.broadcast !== false,
    };
    try {
      await options.consumeExecutionClaim(expected);
    } catch (error) {
      if (error instanceof GovernedVaultError) throw error;
      throw new GovernedVaultError(
        error instanceof Error ? error.message : "Parsed Solana execution claim was rejected",
        "authorization_rejected",
      );
    }

    return this.rawVault.signSolanaTransaction({
      ...request,
      governedParsedSign: createGovernedParsedSolanaSigningGrant({
        agentId: request.agentId,
        broadcast: request.broadcast !== false,
        chainId: request.chainId ?? 101,
        executionPayloadDigest,
        messageDigest: options.messageDigest,
        tenantId: request.tenantId,
      }),
    });
  }
}
