import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgeFileSecretStore } from "@stwd/vault";

const SCRIPT = join(import.meta.dir, "..", "..", "scripts", "migrate-env-secrets.ts");

let dir: string;
let identity: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "migrate-secrets-"));
  const init = await AgeFileSecretStore.initStore(join(dir, "store"));
  identity = init.identity;
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function runScript(
  args: string[],
  env: Record<string, string> = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bun", SCRIPT, ...args], {
    cwd: join(import.meta.dir, "..", ".."),
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  return { code, stdout, stderr };
}

describe("migrate-env-secrets (DUMMY secrets only)", () => {
  test("--from-env onboards dummy values; store can exercise them, plaintext not logged", async () => {
    const manifest = join(dir, "manifest.json");
    await writeFile(
      manifest,
      JSON.stringify({
        secrets: [
          { name: "DUMMY_A", path: "svc/a", description: "dummy a" },
          { name: "DUMMY_B", path: "svc/b" },
        ],
      }),
    );

    const { code, stdout, stderr } = await runScript(
      ["--manifest", manifest, "--store", join(dir, "store"), "--from-env"],
      { DUMMY_A: "dummy-a-value", DUMMY_B: "dummy-b-value" },
    );
    expect(code).toBe(0);
    // Values must NOT appear in stdout/stderr.
    expect(stdout).not.toContain("dummy-a-value");
    expect(stderr).not.toContain("dummy-b-value");
    expect(stdout).toContain("svc/a");
    expect(stdout).toContain("svc/b");

    // Proof the migration actually sealed the right values: exercise them.
    const store = new AgeFileSecretStore({
      storeDir: join(dir, "store"),
      identitySource: { kind: "identity", identity },
    });
    await store.exercise("svc/a", (p) => expect(p).toBe("dummy-a-value"));
    await store.exercise("svc/b", (p) => expect(p).toBe("dummy-b-value"));
  });

  test("--dry-run reports the plan and seals nothing", async () => {
    const manifest = join(dir, "manifest.json");
    await writeFile(manifest, JSON.stringify({ secrets: [{ name: "DUMMY_A", path: "svc/a" }] }));
    const { code, stdout } = await runScript([
      "--manifest",
      manifest,
      "--store",
      join(dir, "store"),
      "--dry-run",
    ]);
    expect(code).toBe(0);
    expect(stdout).toContain("dryRun");
    const store = new AgeFileSecretStore({ storeDir: join(dir, "store") });
    expect((await store.list()).length).toBe(0);
  });

  test("rejects a manifest that carries a value field (names only)", async () => {
    const manifest = join(dir, "bad.json");
    await writeFile(
      manifest,
      JSON.stringify({ secrets: [{ name: "X", path: "x/y", value: "leak" }] }),
    );
    const { code, stderr } = await runScript([
      "--manifest",
      manifest,
      "--store",
      join(dir, "store"),
      "--dry-run",
    ]);
    expect(code).toBe(1);
    expect(stderr).toContain("NAMES ONLY");
  });
});
