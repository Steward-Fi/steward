import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceBundleVerifierScript, writeOwnerOnlyFile } from "../index";

const CLI_ENTRY = join(dirname(dirname(fileURLToPath(import.meta.url))), "index.ts");

describe("evidence bundle offline verification", () => {
  test("verifier resolves to the CLI-shipped script, independent of CWD", () => {
    const script = evidenceBundleVerifierScript();
    // Must be absolute and INSIDE this repo: a CWD-relative path would execute
    // whatever scripts/verify-evidence-bundle.mjs the operator happens to stand
    // in (attacker-writable clone, shared CI workspace).
    expect(isAbsolute(script)).toBe(true);
    expect(script.endsWith(join("scripts", "verify-evidence-bundle.mjs"))).toBe(true);
    expect(existsSync(script)).toBe(true);
  });

  test("audit bundle --verify never executes a CWD decoy verifier and writes 0600", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-verify-"));
    // Stub API: any GET returns a syntactically valid but unsigned bundle, so
    // the SHIPPED verifier fails closed if (and only if) it is the one run.
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => Response.json({ events: [], checkpoint: null }),
    });
    try {
      const decoyDir = join(dir, "scripts");
      mkdirSync(decoyDir);
      const marker = join(dir, "decoy-executed");
      writeFileSync(
        join(decoyDir, "verify-evidence-bundle.mjs"),
        `import { writeFileSync } from "node:fs";\n` +
          `writeFileSync(${JSON.stringify(marker)}, "pwned");\n` +
          "process.exit(0);\n",
      );
      const out = join(dir, "bundle.json");
      // `mode` on writeFile only affects creation. Exercise replacement of a
      // pre-existing permissive file, which must be tightened before data lands.
      writeFileSync(out, "stale");
      chmodSync(out, 0o644);
      const proc = Bun.spawn(
        [
          "bun",
          "run",
          CLI_ENTRY,
          "audit",
          "bundle",
          "--out",
          out,
          "--verify",
          "--api-url",
          `http://127.0.0.1:${server.port}`,
        ],
        { cwd: dir, stdout: "pipe", stderr: "pipe" },
      );
      const [stderr, exitCode] = await Promise.all([new Response(proc.stderr).text(), proc.exited]);

      // The decoy next to the operator's CWD must never run.
      expect(existsSync(marker)).toBe(false);
      // The shipped verifier ran instead and rejected the unsigned bundle.
      expect(exitCode).toBe(1);
      expect(stderr).toContain("Offline audit bundle verification failed");
      // The bundle carries sensitive audit metadata: owner-only from creation.
      expect(statSync(out).mode & 0o777).toBe(0o600);
    } finally {
      server.stop(true);
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15_000);

  test("owner-only output refuses symlinks", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-output-"));
    try {
      const target = join(dir, "target");
      const output = join(dir, "output");
      writeFileSync(target, "untouched");
      symlinkSync(target, output);

      expect(() => writeOwnerOnlyFile(output, "sensitive")).toThrow();
      expect(readFileSync(target, "utf8")).toBe("untouched");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("owner-only output refuses hard links without mutating the target", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-output-"));
    try {
      const target = join(dir, "target");
      const output = join(dir, "output");
      writeFileSync(target, "untouched", { mode: 0o644 });
      linkSync(target, output);

      expect(() => writeOwnerOnlyFile(output, "sensitive")).toThrow(/hard-linked/);
      expect(readFileSync(target, "utf8")).toBe("untouched");
      expect(statSync(target).mode & 0o777).toBe(0o644);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
