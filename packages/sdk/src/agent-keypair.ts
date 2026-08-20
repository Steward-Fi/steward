/**
 * agent-keypair.ts — the agent's identity keypair, the ONLY long-lived secret an
 * agent process holds under the sovereign-custody premise. Everything else
 * (agent token, capability tokens) is short-lived and obtained at runtime via
 * enrollment + issuance.
 *
 * Hard rules baked in here:
 *   - the P-256 private key is imported NON-extractable wherever the runtime
 *     allows it (Node/Bun WebCrypto honours `extractable=false` on `pkcs8`/`jwk`),
 *     so it can sign but can never be re-exported by the client;
 *   - there is NO API on `AgentKeypair` that returns the raw private key — the
 *     only capability exposed is `sign()`;
 *   - `toString`/`toJSON`/inspection are stubbed to a redacted marker so an
 *     accidental `console.log(keypair)` (or JSON serialization into a log line)
 *     can never leak key material.
 *
 * Signature format matches the server verifier (`@stwd/auth verifyP256Signature`,
 * which accepts both P1363 r||s and DER): we emit base64 P1363, identical to the
 * server-side `signP256` test helper, so an enrollment signature produced here
 * verifies against the registered `agent_signers.publicKey`.
 */

const P256_CURVE = "P-256";
const EC_KEY_PARAMS: EcKeyImportParams = { name: "ECDSA", namedCurve: P256_CURVE };
const ECDSA_SIGN_PARAMS: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

const REDACTED = "[AgentKeypair: private key redacted]";

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Accepted private-key source shapes. All map onto one imported CryptoKey. */
export type AgentKeyMaterial =
  | { kind: "pkcs8-base64"; value: string }
  | { kind: "jwk"; value: JsonWebKey }
  | { kind: "crypto-key"; value: CryptoKey };

/**
 * The agent's identity keypair. Construct via the async factories (import is
 * async in WebCrypto); never via `new`. `sign()` is the only key-using method.
 */
export class AgentKeypair {
  /** the imported, non-extractable (where supported) signing key. */
  readonly #privateKey: CryptoKey;

  private constructor(privateKey: CryptoKey) {
    this.#privateKey = privateKey;
  }

  /**
   * Import from a PKCS#8 DER private key encoded as base64 (the format an
   * operator would write to a mounted key file / inject as an env-referenced
   * path). Imported NON-extractable: the returned keypair can sign but the
   * client can never re-export the raw key.
   */
  static async fromPkcs8Base64(pkcs8Base64: string): Promise<AgentKeypair> {
    const bytes = base64ToBytes(pkcs8Base64);
    const key = await crypto.subtle.importKey("pkcs8", toArrayBuffer(bytes), EC_KEY_PARAMS, false, [
      "sign",
    ]);
    return new AgentKeypair(key);
  }

  /**
   * Import from a JWK private key. Imported NON-extractable regardless of the
   * JWK's `ext` flag (we force `extractable=false`).
   */
  static async fromJwk(jwk: JsonWebKey): Promise<AgentKeypair> {
    const key = await crypto.subtle.importKey("jwk", jwk, EC_KEY_PARAMS, false, ["sign"]);
    return new AgentKeypair(key);
  }

  /**
   * Adopt an already-imported CryptoKey (e.g. from a platform keystore / HSM
   * shim). We assert it is a P-256 private signing key and reject anything else,
   * fail-closed. If the caller imported it non-extractable, it stays that way.
   */
  static async fromCryptoKey(key: CryptoKey): Promise<AgentKeypair> {
    if (key.type !== "private") throw new Error("agent key must be a private key");
    const alg = key.algorithm as EcKeyAlgorithm;
    if (alg?.name !== "ECDSA" || alg?.namedCurve !== P256_CURVE) {
      throw new Error("agent key must be an ECDSA P-256 key");
    }
    if (!key.usages.includes("sign")) throw new Error("agent key must allow 'sign'");
    return new AgentKeypair(key);
  }

  /** Unified factory over the accepted source shapes. */
  static async from(material: AgentKeyMaterial): Promise<AgentKeypair> {
    switch (material.kind) {
      case "pkcs8-base64":
        return AgentKeypair.fromPkcs8Base64(material.value);
      case "jwk":
        return AgentKeypair.fromJwk(material.value);
      case "crypto-key":
        return AgentKeypair.fromCryptoKey(material.value);
      default: {
        const _exhaustive: never = material;
        throw new Error(`unsupported agent key material: ${JSON.stringify(_exhaustive)}`);
      }
    }
  }

  /**
   * Sign a canonical string with the identity key, returning a base64 P1363
   * (r||s) signature — the exact shape the server verifier expects for
   * enrollment. Never logs, never returns key material.
   */
  async sign(canonicalString: string): Promise<string> {
    const data = new TextEncoder().encode(canonicalString);
    const sig = new Uint8Array(
      await crypto.subtle.sign(ECDSA_SIGN_PARAMS, this.#privateKey, toArrayBuffer(data)),
    );
    return bytesToBase64(sig);
  }

  // ── leak guards ─────────────────────────────────────────────────────────────
  /** Redacted so `console.log(keypair)` / template interpolation can't leak. */
  toString(): string {
    return REDACTED;
  }
  /** Redacted so `JSON.stringify(keypair)` (e.g. structured logging) can't leak. */
  toJSON(): string {
    return REDACTED;
  }
  /** Node's util.inspect hook — redacted for the same reason. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED;
  }
}
