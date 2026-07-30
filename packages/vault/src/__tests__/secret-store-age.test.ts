import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AgeFileSecretStore,
  assertValidSecretPath,
  SecretAlreadyExistsError,
  SecretNotFoundError,
  type SecretStoreBackend,
  sealToRecipient,
} from "../index";

// A stand-in "live secret" that must NEVER appear in plaintext at rest.
const DUMMY_SECRET = "dummy-discord-bot-token-DO-NOT-USE-1234567890";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "steward-secret-store-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function freshStore(): Promise<{
  store: AgeFileSecretStore;
  identity: string;
  recipient: string;
}> {
  const { recipient, identity } = await AgeFileSecretStore.initStore(dir);
  const store = new AgeFileSecretStore({
    storeDir: dir,
    identitySource: { kind: "identity", identity },
  });
  return { store, identity, recipient };
}

describe("AgeFileSecretStore — put + exercise (no read-back)", () => {
  test("operator seals to recipient; store ingests ciphertext and exercises it", async () => {
    const { store, recipient } = await freshStore();

    // Onboarding: operator encrypts DIRECTLY to the recipient on their machine.
    const sealed = await sealToRecipient(recipient, DUMMY_SECRET);
    expect(sealed).toContain("-----BEGIN AGE ENCRYPTED FILE-----");
    expect(sealed).not.toContain(DUMMY_SECRET);

    const meta = await store.putSealed("discord/soliza-bot-token", sealed, {
      description: "dummy",
    });
    expect(meta.path).toBe("discord/soliza-bot-token");
    expect(meta.version).toBe(1);

    // Exercise: plaintext is handed to a closure, never returned by the store.
    const usedValue = await store.exercise("discord/soliza-bot-token", (plaintext) => {
      expect(plaintext).toBe(DUMMY_SECRET);
      // Simulate a brokered call returning a RESULT, not the secret.
      return { status: 200 };
    });
    expect(usedValue).toEqual({ status: 200 });
  });

  test("NO read-back API exists on the backend surface (the security property)", async () => {
    const { store } = await freshStore();
    const surface = store as unknown as Record<string, unknown>;
    // These would be the obvious plaintext-getter names; none may exist.
    for (const forbidden of ["get", "read", "reveal", "getValue", "decrypt", "getSecret"]) {
      expect(surface[forbidden]).toBeUndefined();
    }
    // The typed interface only offers write + exercise + metadata.
    const iface: SecretStoreBackend = store;
    expect(typeof iface.putSealed).toBe("function");
    expect(typeof iface.exercise).toBe("function");
    expect(typeof iface.list).toBe("function");
    expect(typeof iface.rotateSealed).toBe("function");
    expect(typeof iface.delete).toBe("function");
    expect((iface as unknown as Record<string, unknown>).get).toBeUndefined();
  });

  test("plaintext is NOT present anywhere at rest on disk", async () => {
    const { store, recipient } = await freshStore();
    const sealed = await sealToRecipient(recipient, DUMMY_SECRET);
    await store.putSealed("api/openai", sealed);

    const secretsDir = join(dir, "secrets");
    const files = await readdir(secretsDir);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const contents = await Bun.file(join(secretsDir, file)).text();
      expect(contents).not.toContain(DUMMY_SECRET);
    }
    // recipient.txt is public and must not contain the identity secret key.
    const rec = await Bun.file(join(dir, "recipient.txt")).text();
    expect(rec).not.toContain("AGE-SECRET-KEY");
    expect(rec.trim()).toBe(recipient);
  });
});

describe("AgeFileSecretStore — lifecycle", () => {
  test("stat + list return metadata only, never values", async () => {
    const { store, recipient } = await freshStore();
    await store.putSealed("a/one", await sealToRecipient(recipient, "v1"));
    await store.putSealed("b/two", await sealToRecipient(recipient, "v2"));

    const stat = await store.stat("a/one");
    expect(stat?.path).toBe("a/one");
    expect(JSON.stringify(stat)).not.toContain("v1");

    const list = await store.list();
    expect(list.map((entry) => entry.path)).toEqual(["a/one", "b/two"]);
    expect(JSON.stringify(list)).not.toContain("v1");
    expect(await store.stat("nope/missing")).toBeNull();
  });

  test("put rejects duplicate path unless overwrite; rotate bumps version", async () => {
    const { store, recipient } = await freshStore();
    await store.putSealed("api/token", await sealToRecipient(recipient, "first"));

    await expect(
      store.putSealed("api/token", await sealToRecipient(recipient, "first")),
    ).rejects.toBeInstanceOf(SecretAlreadyExistsError);

    // overwrite=true is allowed for idempotent re-onboarding.
    await store.putSealed("api/token", await sealToRecipient(recipient, "first"), {
      overwrite: true,
    });

    const rotated = await store.rotateSealed(
      "api/token",
      await sealToRecipient(recipient, "second"),
    );
    expect(rotated.version).toBe(2);
    await store.exercise("api/token", (plaintext) => expect(plaintext).toBe("second"));
  });

  test("rotate on a missing path throws SecretNotFoundError", async () => {
    const { store, recipient } = await freshStore();
    await expect(
      store.rotateSealed("ghost", await sealToRecipient(recipient, "x")),
    ).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  test("delete removes ciphertext + metadata; exercise then fails closed", async () => {
    const { store, recipient } = await freshStore();
    await store.putSealed("temp/secret", await sealToRecipient(recipient, "bye"));
    expect(await store.delete("temp/secret")).toBe(true);
    expect(await store.delete("temp/secret")).toBe(false);
    await expect(store.exercise("temp/secret", (p) => p)).rejects.toBeInstanceOf(
      SecretNotFoundError,
    );
  });

  test("exercise fails closed when the identity is unavailable", async () => {
    const { recipient } = await freshStore();
    // A store with NO identity source can onboard + list but cannot decrypt.
    const onboardOnly = new AgeFileSecretStore({ storeDir: dir, identitySource: { kind: "none" } });
    await onboardOnly.putSealed("x/y", await sealToRecipient(recipient, "z"));
    expect((await onboardOnly.list()).length).toBe(1);
    await expect(onboardOnly.exercise("x/y", (p) => p)).rejects.toThrow(/no identity source/);
  });

  test("putSealed rejects non-age ciphertext (fail closed on plaintext)", async () => {
    const { store } = await freshStore();
    await expect(store.putSealed("bad", DUMMY_SECRET)).rejects.toThrow(/armored age file/);
  });
});

describe("AgeFileSecretStore — identity sourcing", () => {
  test("env-var identity source decrypts at boot", async () => {
    const { recipient, identity } = await AgeFileSecretStore.initStore(dir);
    process.env.STEWARD_SECRET_STORE_TEST_ID = identity;
    try {
      const store = new AgeFileSecretStore({
        storeDir: dir,
        identitySource: { kind: "env", var: "STEWARD_SECRET_STORE_TEST_ID" },
      });
      await store.putSealed("k", await sealToRecipient(recipient, "boot-value"));
      await store.exercise("k", (plaintext) => expect(plaintext).toBe("boot-value"));
    } finally {
      process.env.STEWARD_SECRET_STORE_TEST_ID = undefined;
    }
  });

  test("initStore refuses to clobber an existing store", async () => {
    await AgeFileSecretStore.initStore(dir);
    await expect(AgeFileSecretStore.initStore(dir)).rejects.toThrow(/already initialized/);
  });
});

describe("assertValidSecretPath", () => {
  test("accepts slash-separated lowercase paths", () => {
    expect(() => assertValidSecretPath("discord/soliza-bot-token")).not.toThrow();
    expect(() => assertValidSecretPath("a.b_c/1.2.3")).not.toThrow();
  });

  test("rejects traversal, uppercase, empty, and overlong segments", () => {
    expect(() => assertValidSecretPath("../etc/passwd")).toThrow();
    expect(() => assertValidSecretPath("a//b")).toThrow();
    expect(() => assertValidSecretPath("UPPER")).toThrow();
    expect(() => assertValidSecretPath("")).toThrow();
    expect(() => assertValidSecretPath(`x/${"a".repeat(65)}`)).toThrow();
  });
});
