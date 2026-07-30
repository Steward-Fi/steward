import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgeFileSecretStore } from "@stwd/vault";
import { secretsStoreCommand } from "../secrets-store";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "cli-secret-store-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("steward secrets (sealed store CLI)", () => {
  test("init returns recipient + identity and warns identity is shown once", async () => {
    const result = (await secretsStoreCommand("init", { store: dir })) as {
      recipient: string;
      identity: string;
      warning: string;
    };
    expect(result.recipient.startsWith("age1")).toBe(true);
    expect(result.identity.startsWith("AGE-SECRET-KEY-1")).toBe(true);
    expect(result.warning).toContain("ONLY time");
  });

  test("put via --file seals and stores; list shows metadata only", async () => {
    await secretsStoreCommand("init", { store: dir });
    // Write a dummy secret to a temp file (simulates --file onboarding).
    const secretFile = join(dir, "dummy.txt");
    await Bun.write(secretFile, "dummy-value-9999");

    const put = (await secretsStoreCommand("put", {
      store: dir,
      file: secretFile,
      desc: "note",
      __path: "api/openai",
    })) as { onboarded: string; version: number };
    expect(put.onboarded).toBe("api/openai");
    expect(put.version).toBe(1);

    const listed = (await secretsStoreCommand("list", { store: dir })) as {
      secrets: Array<{ path: string }>;
    };
    expect(listed.secrets.map((s) => s.path)).toEqual(["api/openai"]);
    // Ensure the value never leaks through the CLI JSON surface.
    expect(JSON.stringify(listed)).not.toContain("dummy-value-9999");
  });

  test("put refuses --value flag (shell-history leak) — fail closed", async () => {
    await secretsStoreCommand("init", { store: dir });
    await expect(
      secretsStoreCommand("put", { store: dir, value: "leaky", __path: "x/y" }),
    ).rejects.toThrow(/refusing --value/);
  });

  test("there is no 'get' subcommand (write + exercise only)", async () => {
    await secretsStoreCommand("init", { store: dir });
    await expect(secretsStoreCommand("get", { store: dir, __path: "x/y" })).rejects.toThrow(
      /no 'get'/,
    );
  });

  test("recipient subcommand matches the on-disk recipient the store exercises", async () => {
    const init = (await secretsStoreCommand("init", { store: dir })) as {
      recipient: string;
      identity: string;
    };
    const rec = (await secretsStoreCommand("recipient", { store: dir })) as { recipient: string };
    expect(rec.recipient).toBe(init.recipient);

    // End-to-end proof: a value put through the CLI can be exercised with the
    // identity init handed back — the CLI onboards, the runtime exercises.
    const secretFile = join(dir, "s.txt");
    await Bun.write(secretFile, "roundtrip-secret");
    await secretsStoreCommand("put", { store: dir, file: secretFile, __path: "svc/token" });

    const store = new AgeFileSecretStore({
      storeDir: dir,
      identitySource: { kind: "identity", identity: init.identity },
    });
    await store.exercise("svc/token", (plaintext) => expect(plaintext).toBe("roundtrip-secret"));
  });

  test("rm deletes a secret", async () => {
    await secretsStoreCommand("init", { store: dir });
    const secretFile = join(dir, "s.txt");
    await Bun.write(secretFile, "bye");
    await secretsStoreCommand("put", { store: dir, file: secretFile, __path: "temp/x" });
    const rm1 = (await secretsStoreCommand("rm", { store: dir, __path: "temp/x" })) as {
      deleted: boolean;
    };
    expect(rm1.deleted).toBe(true);
  });
});
