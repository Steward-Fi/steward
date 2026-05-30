import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { encryptedKeys, eq, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { KeyStore } from "../keystore";
import { backendFromKeyStore } from "../keystore-backend";
import { type AwsKmsClientLike, KmsEnvelopeKeystore } from "../keystore-kms";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-kms-keystore-master";
const TENANT_ID = "test-kms-tenant";

const openClients: Array<{ close: () => Promise<void> }> = [];

class MockAwsKmsClient implements AwsKmsClientLike {
  private readonly rootKey = randomBytes(32);

  encryptCalls = 0;

  decryptCalls = 0;

  async send(command: unknown): Promise<unknown> {
    const typed = command as { commandName?: string; input?: Record<string, unknown> };
    if (typed.commandName === "EncryptCommand") {
      this.encryptCalls += 1;
      const plaintext = Buffer.from(typed.input?.Plaintext as Uint8Array);
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", this.rootKey, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        CiphertextBlob: Buffer.from(
          JSON.stringify({
            iv: iv.toString("base64"),
            tag: tag.toString("base64"),
            ciphertext: ciphertext.toString("base64"),
          }),
        ),
      };
    }

    if (typed.commandName === "DecryptCommand") {
      this.decryptCalls += 1;
      const blob = JSON.parse(
        Buffer.from(typed.input?.CiphertextBlob as Uint8Array).toString("utf8"),
      ) as {
        iv: string;
        tag: string;
        ciphertext: string;
      };
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.rootKey,
        Buffer.from(blob.iv, "base64"),
      );
      decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
      return {
        Plaintext: Buffer.concat([
          decipher.update(Buffer.from(blob.ciphertext, "base64")),
          decipher.final(),
        ]),
      };
    }

    throw new Error("Unexpected mock KMS command");
  }
}

async function freshVault(keystoreBackend?: KmsEnvelopeKeystore): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "KMS Test Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD, keystoreBackend });
}

describe("KMS envelope keystore", () => {
  beforeEach(() => {
    process.env.NODE_ENV = "test";
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("default AES backend round-trips through the backend seam", async () => {
    const backend = backendFromKeyStore(new KeyStore(MASTER_PASSWORD));
    const privateKey = "0x" + "1".repeat(64);

    const encrypted = await backend.encrypt(privateKey);
    const decrypted = await backend.decrypt(encrypted);

    expect(decrypted).toBe(privateKey);
    expect(encrypted.backend).toBeUndefined();
  });

  test("AWS KMS envelope round-trips with a mocked client", async () => {
    const client = new MockAwsKmsClient();
    const backend = new KmsEnvelopeKeystore({
      provider: "aws",
      keyId: "alias/steward-test",
      client,
    });
    const privateKey = "0x" + "2".repeat(64);

    const encrypted = await backend.encrypt(privateKey, { tenantId: "t1", agentId: "a1" });
    const decrypted = await backend.decrypt(encrypted, { tenantId: "t1", agentId: "a1" });

    expect(decrypted).toBe(privateKey);
    expect(encrypted.backend).toBe("kms-envelope:aws-kms");
    expect(encrypted.wrappedDataKey).toBeTruthy();
    expect(encrypted.salt.startsWith("kms-envelope:v1:")).toBe(true);
    expect(client.encryptCalls).toBe(1);
    expect(client.decryptCalls).toBe(1);
  });

  test("KMS records reject cross-backend decrypt and tampered wrapped keys", async () => {
    const client = new MockAwsKmsClient();
    const kms = new KmsEnvelopeKeystore({ provider: "aws", keyId: "alias/steward-test", client });
    const aes = backendFromKeyStore(new KeyStore(MASTER_PASSWORD));
    const encrypted = await kms.encrypt("0x" + "3".repeat(64));

    expect(() => aes.decrypt(encrypted)).toThrow();

    const tampered = {
      ...encrypted,
      wrappedDataKey: Buffer.from("tampered", "utf8").toString("hex"),
    };
    await expect(kms.decrypt(tampered)).rejects.toThrow();
  });

  test("vault uses a configured KMS backend and persists envelope metadata", async () => {
    const backend = new KmsEnvelopeKeystore({
      provider: "aws",
      keyId: "alias/steward-test",
      client: new MockAwsKmsClient(),
    });
    const vault = await freshVault(backend);
    await vault.createAgent(TENANT_ID, "kms-agent", "KMS Agent");

    const [row] = await getDb()
      .select()
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, "kms-agent"));

    expect(row.salt.startsWith("kms-envelope:v1:")).toBe(true);
    const decrypted = await backend.decrypt({
      ciphertext: row.ciphertext,
      iv: row.iv,
      tag: row.tag,
      salt: row.salt,
    });
    expect(decrypted.startsWith("0x")).toBe(true);
  });

  test("vault constructor falls back to AES when no backend is configured", async () => {
    const vault = await freshVault();
    await vault.createAgent(TENANT_ID, "fallback-agent", "Fallback Agent");

    const [row] = await getDb()
      .select()
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, "fallback-agent"));

    const decrypted = new KeyStore(MASTER_PASSWORD).decrypt({
      ciphertext: row.ciphertext,
      iv: row.iv,
      tag: row.tag,
      salt: row.salt,
    });

    expect(decrypted.startsWith("0x")).toBe(true);
  });
});
