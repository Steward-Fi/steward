import { afterAll, describe, expect, it } from "bun:test";

describe("webhook payload secrecy", () => {
  afterAll(() => {
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("redacts nested mnemonic and private key material before delivery persistence", async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "webhook-redaction-master-password";
    const { redactWebhookSecrets } = await import("../services/webhook-redaction");

    expect(
      redactWebhookSecrets({
        walletId: "wallet-1",
        recovery: {
          mnemonic:
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
          recoveryMnemonic:
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
          recovery_phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
          "seed-phrase":
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        },
        evm: {
          privateKey: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "private-key": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          exportedPlaintextPrivateKey:
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          publicKey: "0x04public",
          address: "0x0000000000000000000000000000000000000001",
        },
        oauth: {
          accessToken: "access-token-value",
          access_token: "access-token-snake-value",
          oauthAccessTokenHash: "sha256:access-token-hash",
          idToken: "id-token-value",
          id_token: "id-token-snake-value",
          jwt: "jwt-value",
          refresh_token: "refresh-token-value",
          sessionToken: "session-token-value",
          clientSecret: "oauth-client-secret",
          authorization: "Bearer oauth-token",
          bearer_token: "bearer-token-snake-value",
        },
        pregenerated: {
          claimToken: "stwd_claim_secret",
        },
        signer: {
          credentialSecret: "stwd_signer_secret",
          credential_secret: "stwd_signer_secret_snake",
          signerSecret: "signer-header-secret",
          signer_secret: "signer-header-secret-snake",
          "x-steward-signer-secret": "signer-header-secret-hyphen",
        },
        provider: {
          apiKey: "provider-api-key",
          api_key: "provider-api-key-snake",
        },
        token: "native",
      }),
    ).toEqual({
      walletId: "wallet-1",
      recovery: {
        mnemonic: "[REDACTED]",
        recoveryMnemonic: "[REDACTED]",
        recovery_phrase: "[REDACTED]",
        "seed-phrase": "[REDACTED]",
      },
      evm: {
        privateKey: "[REDACTED]",
        "private-key": "[REDACTED]",
        exportedPlaintextPrivateKey: "[REDACTED]",
        publicKey: "0x04public",
        address: "0x0000000000000000000000000000000000000001",
      },
      oauth: {
        accessToken: "[REDACTED]",
        access_token: "[REDACTED]",
        oauthAccessTokenHash: "[REDACTED]",
        idToken: "[REDACTED]",
        id_token: "[REDACTED]",
        jwt: "[REDACTED]",
        refresh_token: "[REDACTED]",
        sessionToken: "[REDACTED]",
        clientSecret: "[REDACTED]",
        authorization: "[REDACTED]",
        bearer_token: "[REDACTED]",
      },
      pregenerated: {
        claimToken: "[REDACTED]",
      },
      signer: {
        credentialSecret: "[REDACTED]",
        credential_secret: "[REDACTED]",
        signerSecret: "[REDACTED]",
        signer_secret: "[REDACTED]",
        "x-steward-signer-secret": "[REDACTED]",
      },
      provider: {
        apiKey: "[REDACTED]",
        api_key: "[REDACTED]",
      },
      token: "native",
    });
  });
});
