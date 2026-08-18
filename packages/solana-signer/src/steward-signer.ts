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

import { createPublicKey, verify } from "node:crypto";
import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { type PolicyResult, StewardApiError, StewardClient } from "@stwd/sdk";

/** Policy fields for the server's explicitly unsafe blind-signing mode. For
 * parsed transactions Steward rejects conflicts; for unparsed instructions
 * these are unverifiable caller assertions and must not be trusted. */
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
  try {
    if (err instanceof StewardSignerError) return err;
  } catch {
    return new StewardSignerError("api", "Steward signing service failed");
  }
  try {
    if (!(err instanceof StewardApiError)) {
      let message = "Steward signing service failed";
      try {
        if (err instanceof Error && typeof err.message === "string" && err.message.trim()) {
          message = err.message;
        }
      } catch {
        // A Proxy or exotic thrown value can trap instanceof/property access.
        // Error handling must remain fail-closed and non-throwing.
      }
      return new StewardSignerError("api", message, { cause: err });
    }
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
  } catch {
    // Never coerce an unknown thrown value with String(): Symbol.toPrimitive,
    // valueOf, message, or prototype traps could throw a second time and leave
    // the bridge request hanging instead of returning a bounded 502.
    return new StewardSignerError("api", "Steward signing service failed");
  }
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

/** Solana's serialized transaction packet limit. Reject larger inputs locally
 * before allocating, parsing, or sending policy-bearing bytes to Steward. */
export const SOLANA_MAX_TRANSACTION_BYTES = 1232;

function decodeCanonicalTransactionBase64(value: string): Uint8Array {
  const maxBase64Length = Math.ceil(SOLANA_MAX_TRANSACTION_BYTES / 3) * 4;
  if (
    value.length === 0 ||
    value.length > maxBase64Length ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new StewardSignerError("api", "invalid canonical base64 Solana transaction");
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length === 0 ||
    decoded.length > SOLANA_MAX_TRANSACTION_BYTES ||
    decoded.toString("base64") !== value
  ) {
    throw new StewardSignerError("api", "invalid canonical base64 Solana transaction");
  }
  return decoded;
}

function isVersioned(tx: Transaction | VersionedTransaction): tx is VersionedTransaction {
  return "version" in tx;
}

function assertSameBytes(actual: Uint8Array, expected: Uint8Array, message: string): void {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    throw new StewardSignerError("api", message);
  }
}

function verifySolanaSignature(
  publicKey: PublicKey,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  // RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(publicKey.toBytes()),
  ]);
  return verify(
    null,
    Buffer.from(message),
    createPublicKey({ key: spki, format: "der", type: "spki" }),
    signature,
  );
}

function validateSignedResponse(
  submitted: Transaction | VersionedTransaction,
  returned: Transaction | VersionedTransaction,
  publicKey: PublicKey,
): void {
  if (isVersioned(submitted) !== isVersioned(returned)) {
    throw new StewardSignerError("api", "Steward returned a different Solana transaction format");
  }

  if (isVersioned(submitted) && isVersioned(returned)) {
    const submittedMessage = submitted.message.serialize();
    assertSameBytes(
      returned.message.serialize(),
      submittedMessage,
      "Steward returned signatures for a different Solana message",
    );
    const required = submitted.message.header.numRequiredSignatures;
    if (
      submitted.signatures.length !== required ||
      returned.signatures.length !== required ||
      returned.signatures.length !== submitted.signatures.length
    ) {
      throw new StewardSignerError("api", "Steward returned a mismatched signature-slot count");
    }
    const signerIndex = submitted.message.staticAccountKeys
      .slice(0, required)
      .findIndex((key) => key.equals(publicKey));
    if (signerIndex < 0) {
      throw new StewardSignerError(
        "api",
        "the Steward Solana address is not a required transaction signer",
      );
    }
    for (let index = 0; index < submitted.signatures.length; index += 1) {
      const prior = submitted.signatures[index];
      if (index !== signerIndex) {
        assertSameBytes(
          returned.signatures[index] ?? new Uint8Array(),
          prior,
          "Steward changed a co-signer signature slot",
        );
      }
    }
    const stewardSignature = returned.signatures[signerIndex];
    if (
      !stewardSignature ||
      !verifySolanaSignature(publicKey, submittedMessage, stewardSignature)
    ) {
      throw new StewardSignerError("api", "Steward returned an invalid Solana signature");
    }
    return;
  }

  const submittedLegacy = submitted as Transaction;
  const returnedLegacy = returned as Transaction;
  const submittedMessage = submittedLegacy.serializeMessage();
  assertSameBytes(
    returnedLegacy.serializeMessage(),
    submittedMessage,
    "Steward returned signatures for a different Solana message",
  );
  if (returnedLegacy.signatures.length !== submittedLegacy.signatures.length) {
    throw new StewardSignerError("api", "Steward returned a mismatched signature-slot count");
  }
  const signerIndex = submittedLegacy.signatures.findIndex((entry) =>
    entry.publicKey.equals(publicKey),
  );
  if (signerIndex < 0) {
    throw new StewardSignerError(
      "api",
      "the Steward Solana address is not a required transaction signer",
    );
  }
  for (let index = 0; index < submittedLegacy.signatures.length; index += 1) {
    const prior = submittedLegacy.signatures[index]?.signature;
    if (index !== signerIndex) {
      const returnedSignature = returnedLegacy.signatures[index]?.signature;
      if (prior === null || prior === undefined) {
        if (returnedSignature !== null && returnedSignature !== undefined) {
          throw new StewardSignerError("api", "Steward changed a co-signer signature slot");
        }
      } else {
        if (!returnedSignature) {
          throw new StewardSignerError("api", "Steward changed a co-signer signature slot");
        }
        assertSameBytes(returnedSignature, prior, "Steward changed a co-signer signature slot");
      }
    }
  }
  const stewardSignature = returnedLegacy.signatures[signerIndex]?.signature;
  if (!stewardSignature || !verifySolanaSignature(publicKey, submittedMessage, stewardSignature)) {
    throw new StewardSignerError("api", "Steward returned an invalid Solana signature");
  }
}

function deserializeTransaction(bytes: Uint8Array): Transaction | VersionedTransaction {
  // A serialized transaction starts with compact-u16 signature count and slots;
  // the following message byte has its high bit set for versioned messages.
  let signatureCount = 0;
  let bytesRead = 0;
  for (let shift = 0; ; shift += 7) {
    const byte = bytes[bytesRead];
    if (byte === undefined || shift > 21)
      throw new StewardSignerError("api", "invalid Solana transaction");
    bytesRead += 1;
    signatureCount |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
  }
  const messageByte = bytes[bytesRead + signatureCount * 64];
  if (messageByte === undefined) throw new StewardSignerError("api", "invalid Solana transaction");
  const transaction =
    (messageByte & 0x80) !== 0 ? VersionedTransaction.deserialize(bytes) : Transaction.from(bytes);
  // web3.js deserializers accept a valid transaction prefix followed by
  // arbitrary trailing bytes; Transaction.from also normalizes extra legacy
  // signature records away. Reject every parser-differential representation by
  // requiring the parsed transaction to serialize to the exact submitted byte
  // string. This applies to both caller input and Steward's signed response.
  const canonical = isVersioned(transaction)
    ? transaction.serialize()
    : transaction.serialize({ requireAllSignatures: false, verifySignatures: false });
  if (!Buffer.from(canonical).equals(Buffer.from(bytes))) {
    throw new StewardSignerError("api", "non-canonical Solana transaction encoding");
  }
  return transaction;
}

function serializeTransaction(tx: Transaction | VersionedTransaction): Uint8Array {
  return isVersioned(tx)
    ? tx.serialize()
    : tx.serialize({ requireAllSignatures: false, verifySignatures: false });
}

function malformedSuccessResponse(message: string, cause: unknown): StewardSignerError {
  try {
    if (cause instanceof StewardSignerError) return cause;
  } catch {
    // A hostile Proxy can trap prototype access. Always return a bounded error.
  }
  return new StewardSignerError("api", message, { cause });
}

/** Build a signer for one Steward agent. Async because it resolves the agent's
 *  Solana address from the vault unless `address` is supplied. */
export async function createStewardSolanaSigner(
  config: StewardSolanaSignerConfig,
): Promise<StewardSolanaSigner> {
  if (!config.agentId.trim()) {
    throw new StewardSignerError("api", "agentId must not be empty");
  }
  const chainId = config.chainId ?? 101;
  if (chainId !== 101 && chainId !== 102) {
    throw new StewardSignerError("api", "Solana chainId must be 101 (mainnet) or 102 (devnet)");
  }
  const client =
    config.client ??
    new StewardClient({
      baseUrl: requireBaseUrl(config),
      bearerToken: config.bearerToken,
      apiKey: config.apiKey,
      tenantId: config.tenantId,
    });
  const { agentId } = config;

  let address = config.address;
  if (!address) {
    let response: Awaited<ReturnType<StewardClient["getAddresses"]>>;
    try {
      response = await client.getAddresses(agentId);
    } catch (err) {
      throw toSignerError(err);
    }
    try {
      if (!response || !Array.isArray(response.addresses)) {
        throw new Error("addresses is not an array");
      }
      address = response.addresses.find(
        (entry) =>
          entry !== null &&
          typeof entry === "object" &&
          entry.chainFamily === "solana" &&
          typeof entry.address === "string",
      )?.address;
    } catch (err) {
      throw malformedSuccessResponse("Steward returned a malformed address response", err);
    }
    if (!address) {
      throw new StewardSignerError(
        "api",
        `Agent ${agentId} has no Solana wallet in Steward (legacy EVM-only agent?)`,
      );
    }
  }
  let publicKey: PublicKey;
  try {
    publicKey = new PublicKey(address);
  } catch (err) {
    throw new StewardSignerError("api", "Steward returned an invalid Solana address", {
      cause: err,
    });
  }

  async function signSerializedTransaction(
    txBase64: string,
    hints?: SolanaPolicyHints,
  ): Promise<string> {
    let submitted: Transaction | VersionedTransaction;
    try {
      submitted = deserializeTransaction(decodeCanonicalTransactionBase64(txBase64));
    } catch (err) {
      throw toSignerError(err);
    }
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
    try {
      if (!result || typeof result !== "object" || typeof result.signature !== "string") {
        throw new Error("signing response is not an object with a signature");
      }
      if (result.broadcast !== false) {
        throw new StewardSignerError(
          "api",
          "Steward did not prove that broadcast:false was honored",
        );
      }
      if (result.chainId !== chainId) {
        throw new StewardSignerError("api", "Steward returned a mismatched Solana chainId");
      }
      const returned = deserializeTransaction(decodeCanonicalTransactionBase64(result.signature));
      validateSignedResponse(submitted, returned, publicKey);
    } catch (err) {
      throw malformedSuccessResponse("Steward returned a malformed signing response", err);
    }
    // With broadcast:false the route returns the FULL signed transaction,
    // base64-serialized, in the `signature` field.
    return result.signature;
  }

  async function signOne<T extends Transaction | VersionedTransaction>(tx: T): Promise<T> {
    // requireAllSignatures:false preserves partial signatures already added by
    // co-signing keypairs (mint keypairs, protocol minters) through the round trip.
    const bytes = serializeTransaction(tx);
    const hints = config.hints?.(tx);
    let currentBytes: Uint8Array;
    try {
      currentBytes = serializeTransaction(tx);
    } catch (err) {
      throw new StewardSignerError("api", "caller transaction changed while preparing signing", {
        cause: err,
      });
    }
    assertSameBytes(currentBytes, bytes, "caller transaction changed while preparing signing");
    const signedB64 = await signSerializedTransaction(Buffer.from(bytes).toString("base64"), hints);
    try {
      currentBytes = serializeTransaction(tx);
    } catch (err) {
      throw new StewardSignerError("api", "caller transaction changed during signing", {
        cause: err,
      });
    }
    assertSameBytes(currentBytes, bytes, "caller transaction changed during signing");
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
