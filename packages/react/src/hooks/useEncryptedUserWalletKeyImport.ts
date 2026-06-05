import type {
  EncryptedUserWalletKeyImportInitResult,
  EncryptedUserWalletKeyImportResult,
  EncryptedUserWalletKeyImportSubmitInput,
  StewardClient,
} from "@stwd/sdk";
import { useCallback, useState } from "react";
import { useSteward } from "./useSteward.js";

export type UserWalletImportChain = "evm" | "solana";

export interface UserWalletKeyImportInput {
  chain: UserWalletImportChain;
  privateKey: string;
  walletIndex?: number;
}

export interface UseEncryptedUserWalletKeyImportResult {
  importKey: (input: UserWalletKeyImportInput) => Promise<EncryptedUserWalletKeyImportResult>;
  isImporting: boolean;
  error: Error | null;
  result: EncryptedUserWalletKeyImportResult | null;
  reset: () => void;
}

type UserWalletKeyImportClient = Pick<
  StewardClient,
  "initializeEncryptedUserWalletKeyImport" | "submitEncryptedUserWalletKeyImport"
>;

type ImportCrypto = Pick<Crypto, "getRandomValues" | "subtle">;

const textEncoder = new TextEncoder();

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return "privateKey" in value && "publicKey" in value;
}

function getBrowserCrypto(): ImportCrypto {
  const cryptoImpl = globalThis.crypto;
  if (!cryptoImpl?.subtle || typeof cryptoImpl.getRandomValues !== "function") {
    throw new Error("Encrypted wallet import requires browser WebCrypto support");
  }
  return cryptoImpl;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+={0,2}$/u.test(value)) {
    throw new Error("Encrypted import public key is not valid base64url");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function importInfo(init: EncryptedUserWalletKeyImportInitResult): Uint8Array {
  const { tenantId, userId, agentId, chain, walletIndex, appClientId } = init.aad;
  return textEncoder.encode(
    `steward:user-wallet-import:v1:${tenantId}:${userId}:${agentId}:${chain}:${walletIndex}:${appClientId ?? ""}:${init.importSessionId}`,
  );
}

export async function createEncryptedUserWalletKeyImportEnvelope(
  init: EncryptedUserWalletKeyImportInitResult,
  privateKey: string,
  cryptoImpl: ImportCrypto = getBrowserCrypto(),
): Promise<EncryptedUserWalletKeyImportSubmitInput> {
  if (init.algorithm !== "X25519-HKDF-SHA256-AES-256-GCM") {
    throw new Error(`Unsupported encrypted wallet import algorithm: ${init.algorithm}`);
  }

  const serverPublicKey = await cryptoImpl.subtle.importKey(
    "spki",
    toArrayBuffer(base64UrlDecode(init.publicKey)),
    { name: "X25519" } as AlgorithmIdentifier,
    false,
    [],
  );
  const ephemeralKeys = await cryptoImpl.subtle.generateKey(
    { name: "X25519" } as AlgorithmIdentifier,
    true,
    ["deriveBits"],
  );
  if (!isCryptoKeyPair(ephemeralKeys)) {
    throw new Error("Encrypted wallet import key exchange failed");
  }

  const sharedSecret = new Uint8Array(
    await cryptoImpl.subtle.deriveBits(
      { name: "X25519", public: serverPublicKey } as AlgorithmIdentifier,
      ephemeralKeys.privateKey,
      256,
    ),
  );
  const hkdfKey = await cryptoImpl.subtle.importKey("raw", sharedSecret, "HKDF", false, [
    "deriveKey",
  ]);
  sharedSecret.fill(0);

  const aesKey = await cryptoImpl.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(new Uint8Array()),
      info: toArrayBuffer(importInfo(init)),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const plaintext = textEncoder.encode(privateKey);
  const encrypted = new Uint8Array(
    await cryptoImpl.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: toArrayBuffer(textEncoder.encode(init.importSessionId)),
        tagLength: 128,
      },
      aesKey,
      plaintext,
    ),
  );
  plaintext.fill(0);

  const tagLength = 16;
  const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);
  const tag = encrypted.slice(encrypted.byteLength - tagLength);
  encrypted.fill(0);

  return {
    importSessionId: init.importSessionId,
    ephemeralPublicKey: base64UrlEncode(
      new Uint8Array(await cryptoImpl.subtle.exportKey("spki", ephemeralKeys.publicKey)),
    ),
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag),
    walletIndex: init.aad.walletIndex,
  };
}

export async function encryptedUserWalletKeyImport(
  client: UserWalletKeyImportClient,
  input: UserWalletKeyImportInput,
  cryptoImpl?: ImportCrypto,
): Promise<EncryptedUserWalletKeyImportResult> {
  const init = await client.initializeEncryptedUserWalletKeyImport(input.chain, {
    walletIndex: input.walletIndex,
  });
  const envelope = await createEncryptedUserWalletKeyImportEnvelope(
    init,
    input.privateKey,
    cryptoImpl,
  );
  return client.submitEncryptedUserWalletKeyImport(envelope);
}

export function useEncryptedUserWalletKeyImport(): UseEncryptedUserWalletKeyImportResult {
  const { client } = useSteward();
  const [isImporting, setIsImporting] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [result, setResult] = useState<EncryptedUserWalletKeyImportResult | null>(null);

  const reset = useCallback(() => {
    setError(null);
    setResult(null);
  }, []);

  const importKey = useCallback(
    async (input: UserWalletKeyImportInput) => {
      setIsImporting(true);
      setError(null);
      setResult(null);
      try {
        const imported = await encryptedUserWalletKeyImport(client, input);
        setResult(imported);
        return imported;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        setError(error);
        throw error;
      } finally {
        setIsImporting(false);
      }
    },
    [client],
  );

  return {
    importKey,
    isImporting,
    error,
    result,
    reset,
  };
}
