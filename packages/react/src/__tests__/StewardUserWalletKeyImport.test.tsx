import { beforeEach, describe, expect, mock, test } from "bun:test";
import { generateKeyPairSync, hkdfSync } from "node:crypto";
import type { EncryptedUserWalletKeyImportInitResult } from "@stwd/sdk";
import * as React from "react";
import { renderToString } from "react-dom/server";

let isAuthenticated = true;

mock.module("../hooks/useAuth.js", () => ({
  useAuth: () => ({
    isAuthenticated,
    isLoading: false,
    user: isAuthenticated ? { id: "user_123", email: "a@example.com" } : null,
    session: null,
  }),
}));

mock.module("../hooks/useSteward.js", () => ({
  useSteward: () => ({
    client: {},
    agentId: "agent_root",
    features: {},
    theme: {},
    tenantConfig: null,
    isLoading: false,
    pollInterval: 30000,
  }),
}));

const { StewardUserWalletKeyImport } = await import("../components/StewardUserWalletKeyImport.js");
const {
  base64UrlDecode,
  base64UrlEncode,
  createEncryptedUserWalletKeyImportEnvelope,
  encryptedUserWalletKeyImport,
} = await import("../hooks/useEncryptedUserWalletKeyImport.js");

function render(props: Record<string, unknown> = {}) {
  return renderToString(React.createElement(StewardUserWalletKeyImport, props));
}

function serverInit(): EncryptedUserWalletKeyImportInitResult & {
  serverPrivateKey: CryptoKeyPair["privateKey"];
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    importSessionId: "uwimp_test",
    publicKey: base64UrlEncode(publicKey.export({ type: "spki", format: "der" }) as Uint8Array),
    algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
    expiresAt: "2026-06-05T12:00:00.000Z",
    aad: {
      importSessionId: "uwimp_test",
      tenantId: "personal-user-1",
      userId: "user-1",
      agentId: "user-wallet-user-1-2",
      chain: "evm",
      walletIndex: 2,
      appClientId: "native-ios",
    },
    serverPrivateKey: privateKey as never,
  };
}

describe("<StewardUserWalletKeyImport />", () => {
  beforeEach(() => {
    isAuthenticated = true;
  });

  test("renders import controls without rendering a private key value", () => {
    const html = render({ walletIndex: 2 });
    expect(html).toContain('data-testid="stwd-user-wallet-key-import"');
    expect(html).toContain("import private key");
    expect(html).toContain("wallet index");
    expect(html).not.toContain("privateKey");
  });

  test("renders an authenticated disabled state while signed out", () => {
    isAuthenticated = false;
    const html = render();
    expect(html).toContain("sign in to import");
    expect(html).toContain("disabled");
  });

  test("creates an API-compatible X25519/HKDF/AES-GCM envelope", async () => {
    const init = serverInit();
    const envelope = await createEncryptedUserWalletKeyImportEnvelope(init, "0xsecret");
    expect(envelope.importSessionId).toBe("uwimp_test");
    expect(envelope.walletIndex).toBe(2);
    expect(envelope).not.toHaveProperty("privateKey");
    expect(JSON.stringify(envelope)).not.toContain("0xsecret");

    const clientPublicKey = await crypto.subtle.importKey(
      "spki",
      base64UrlDecode(envelope.ephemeralPublicKey),
      { name: "X25519" } as AlgorithmIdentifier,
      false,
      [],
    );
    const serverPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      init.serverPrivateKey.export({ type: "pkcs8", format: "der" }) as Uint8Array,
      { name: "X25519" } as AlgorithmIdentifier,
      false,
      ["deriveBits"],
    );
    const sharedSecret = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "X25519", public: clientPublicKey } as AlgorithmIdentifier,
        serverPrivateKey,
        256,
      ),
    );
    const info = new TextEncoder().encode(
      "steward:user-wallet-import:v1:personal-user-1:user-1:user-wallet-user-1-2:evm:2:native-ios:uwimp_test",
    );
    const aesKey = hkdfSync("sha256", sharedSecret, new Uint8Array(), info, 32);
    const ciphertext = base64UrlDecode(envelope.ciphertext);
    const tag = base64UrlDecode(envelope.tag);

    const decipher = await import("node:crypto").then(({ createDecipheriv }) =>
      createDecipheriv("aes-256-gcm", aesKey as never, base64UrlDecode(envelope.iv) as never),
    );
    decipher.setAAD(new TextEncoder().encode("uwimp_test") as never);
    decipher.setAuthTag(tag as never);
    const plaintext = Buffer.concat([
      decipher.update(ciphertext as never),
      decipher.final(),
    ]).toString("utf8");
    expect(plaintext).toBe("0xsecret");
  });

  test("uses SDK init and submit helpers without submitting plaintext", async () => {
    const init = serverInit();
    const submittedBodies: unknown[] = [];
    const client = {
      initializeEncryptedUserWalletKeyImport: mock(async () => init),
      submitEncryptedUserWalletKeyImport: mock(async (body: unknown) => {
        submittedBodies.push(body);
        return {
          agentId: "user-wallet-user-1-2",
          walletAddress: "0xabc0000000000000000000000000000000000def",
          chain: "evm",
          walletIndex: 2,
          imported: true,
        };
      }),
    };

    const result = await encryptedUserWalletKeyImport(client, {
      chain: "evm",
      walletIndex: 2,
      privateKey: "0xsecret",
    });

    expect(client.initializeEncryptedUserWalletKeyImport).toHaveBeenCalledWith("evm", {
      walletIndex: 2,
    });
    expect(client.submitEncryptedUserWalletKeyImport).toHaveBeenCalledTimes(1);
    expect(submittedBodies[0]).not.toHaveProperty("privateKey");
    expect(JSON.stringify(submittedBodies)).not.toContain("0xsecret");
    expect(result.imported).toBe(true);
  });
});
