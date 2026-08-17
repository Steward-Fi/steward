// Client-side Solana signer backed by the Steward governed vault.
//
// Exposes the standard wallet-adapter signer shape, the same structural type
// Phantom exposes and the same one @iqlabs-official/solana-sdk calls WalletSigner:
//
//   { publicKey, signTransaction(tx), signAllTransactions(txs) }
//
// so any consumer that accepts an external signer (the AgentNet MCP server,
// an iqlabs SDK writer, a wallet-adapter app) can hold a Steward-governed key
// without ever seeing key material. Every signature goes through
// POST /vault/:agentId/sign-solana with broadcast:false, which means:
//
//   - policy runs server-side on the REAL transaction bytes (spoof-resistant),
//   - the caller keeps its own send+confirm path (sendTx and friends),
//   - refusals surface here as typed StewardSignerError values, never raw HTTP.
//
// Sign-only by design: this module never broadcasts and never touches keys.

import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { type PolicyResult, StewardApiError, StewardClient } from "@stwd/sdk";

/** Advisory fields for Steward's audited blind-signing path (instructions the
 *  server cannot decode). The server treats them as hints only and rejects
 *  conflicts with the parsed transaction, so passing them is always safe. */
export interface SolanaPolicyHints {
  to?: string;
  value?: string;
}

export type StewardSignerErrorKind = "policy_rejected" | "pending_approval" | "auth" | "api";

/** Every failure from the signer, normalized. `kind` tells the caller whether
 *  a human can fix it (policy_rejected, pending_approval), the credentials are
 *  wrong (auth), or the API misbehaved (api). */
export class StewardSignerError extends Error {
  readonly kind: StewardSignerErrorKind;
  readonly status?: number;
  readonly txId?: string;
  readonly policyResults?: PolicyResult[];

  constructor(
    kind: StewardSignerErrorKind,
    message: string,
    options: {
      status?: number;
      txId?: string;
      policyResults?: PolicyResult[];
      cause?: unknown;
    } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "StewardSignerError";
    this.kind = kind;
    this.status = options.status;
    this.txId = options.txId;
    this.policyResults = options.policyResults;
  }
}

function failedRuleSummary(results: PolicyResult[] | undefined): string {
  const failed = (results ?? []).filter((r) => !r.passed);
  if (failed.length === 0) return "";
  return `: ${failed.map((r) => r.reason ?? r.type).join("; ")}`;
}

/** Map any thrown value from the Steward client into a StewardSignerError. */
export function toSignerError(err: unknown): StewardSignerError {
  if (err instanceof StewardSignerError) return err;
  if (err instanceof StewardApiError) {
    const data = (err.data ?? {}) as {
      txId?: string;
      results?: PolicyResult[];
      status?: string;
    };
    const carried = {
      status: err.status,
      txId: data.txId,
      policyResults: data.results,
      cause: err,
    };
    if (data.status === "pending_approval") {
      return new StewardSignerError(
        "pending_approval",
        `Steward queued the transaction for manual approval (txId ${data.txId ?? "unknown"}). A signer cannot wait on a human; approve it in Steward and retry the operation.`,
        carried,
      );
    }
    if (err.status === 403 && data.results) {
      return new StewardSignerError(
        "policy_rejected",
        `Steward policy rejected the transaction${failedRuleSummary(data.results)}`,
        carried,
      );
    }
    if (err.status === 422) {
      return new StewardSignerError(
        "policy_rejected",
        `Steward refused to sign: ${err.message}`,
        carried,
      );
    }
    if (err.status === 401 || err.status === 403) {
      return new StewardSignerError(
        "auth",
        `Steward rejected the credentials: ${err.message}`,
        carried,
      );
    }
    return new StewardSignerError(
      "api",
      `Steward API error (${err.status}): ${err.message}`,
      carried,
    );
  }
  return new StewardSignerError("api", err instanceof Error ? err.message : String(err), {
    cause: err,
  });
}

export interface StewardSolanaSignerConfig {
  /** Agent whose vault key signs. */
  agentId: string;
  /** Steward API base URL, e.g. http://127.0.0.1:3000. Ignored when `client` is given. */
  baseUrl?: string;
  /** Agent-scoped bearer JWT. One of bearerToken, apiKey, or client is required. */
  bearerToken?: string;
  /** API-key auth alternative (X-Steward-Key). */
  apiKey?: string;
  /** Multi-tenant header (X-Steward-Tenant), when the deployment needs it. */
  tenantId?: string;
  /** Preconfigured client; wins over baseUrl/bearerToken/apiKey/tenantId. */
  client?: StewardClient;
  /** Solana chain id understood by Steward: 101 mainnet (default), 102 devnet. */
  chainId?: number;
  /** Skip the /addresses round trip when the agent's Solana address is known. */
  address?: string;
  /** Per-transaction advisory hints for the audited blind-signing path. */
  hints?: (tx: Transaction | VersionedTransaction) => SolanaPolicyHints | undefined;
}

export interface StewardSolanaSigner {
  /** Base58 form of publicKey, for callers that want the string. */
  readonly address: string;
  readonly publicKey: PublicKey;
  signTransaction<T extends Transaction | VersionedTransaction>(tx: T): Promise<T>;
  signAllTransactions<T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]>;
  /** One round trip for callers that already hold serialized bytes (the HTTP bridge). */
  signSerializedTransaction(txBase64: string, hints?: SolanaPolicyHints): Promise<string>;
}

function isVersioned(tx: Transaction | VersionedTransaction): tx is VersionedTransaction {
  return "version" in tx;
}

/** Build a signer for one Steward agent. Async because it resolves the agent's
 *  Solana address from the vault unless `address` is supplied. */
export async function createStewardSolanaSigner(
  config: StewardSolanaSignerConfig,
): Promise<StewardSolanaSigner> {
  const client =
    config.client ??
    new StewardClient({
      baseUrl: requireBaseUrl(config),
      bearerToken: config.bearerToken,
      apiKey: config.apiKey,
      tenantId: config.tenantId,
    });
  const { agentId } = config;
  const chainId = config.chainId ?? 101;

  let address = config.address;
  if (!address) {
    let addresses: Array<{ chainFamily: string; address: string }>;
    try {
      ({ addresses } = await client.getAddresses(agentId));
    } catch (err) {
      throw toSignerError(err);
    }
    address = addresses.find((a) => a.chainFamily === "solana")?.address;
    if (!address) {
      throw new StewardSignerError(
        "api",
        `Agent ${agentId} has no Solana wallet in Steward (legacy EVM-only agent?)`,
      );
    }
  }
  const publicKey = new PublicKey(address);

  async function signSerializedTransaction(
    txBase64: string,
    hints?: SolanaPolicyHints,
  ): Promise<string> {
    let result: Awaited<ReturnType<StewardClient["signSolanaTransaction"]>>;
    try {
      // The SDK input type does not model the advisory to/value hints the
      // route accepts, so widen at the call; extra JSON fields ride along.
      result = await client.signSolanaTransaction(agentId, {
        transaction: txBase64,
        chainId,
        broadcast: false,
        ...(hints?.to !== undefined ? { to: hints.to } : {}),
        ...(hints?.value !== undefined ? { value: hints.value } : {}),
      } as Parameters<StewardClient["signSolanaTransaction"]>[1]);
    } catch (err) {
      throw toSignerError(err);
    }
    if (result.broadcast) {
      throw new StewardSignerError(
        "api",
        "Steward broadcast the transaction although broadcast:false was requested",
      );
    }
    // With broadcast:false the route returns the FULL signed transaction,
    // base64-serialized, in the `signature` field.
    return result.signature;
  }

  async function signOne<T extends Transaction | VersionedTransaction>(tx: T): Promise<T> {
    // requireAllSignatures:false preserves partial signatures already added by
    // co-signing keypairs (mint keypairs, protocol minters) through the round trip.
    const bytes = isVersioned(tx)
      ? tx.serialize()
      : tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const signedB64 = await signSerializedTransaction(
      Buffer.from(bytes).toString("base64"),
      config.hints?.(tx),
    );
    const signedBytes = Buffer.from(signedB64, "base64");
    // Copy signatures back onto the caller's object so identity is preserved,
    // the way in-process keypair signers mutate and return the same tx.
    if (isVersioned(tx)) {
      tx.signatures = VersionedTransaction.deserialize(signedBytes).signatures;
    } else {
      tx.signatures = Transaction.from(signedBytes).signatures;
    }
    return tx;
  }

  return {
    address,
    publicKey,
    signTransaction: signOne,
    async signAllTransactions<T extends Transaction | VersionedTransaction>(
      txs: T[],
    ): Promise<T[]> {
      for (const tx of txs) await signOne(tx);
      return txs;
    },
    signSerializedTransaction,
  };
}

function requireBaseUrl(config: StewardSolanaSignerConfig): string {
  if (!config.baseUrl) {
    throw new StewardSignerError(
      "api",
      "createStewardSolanaSigner needs either `client` or `baseUrl`",
    );
  }
  return config.baseUrl;
}
