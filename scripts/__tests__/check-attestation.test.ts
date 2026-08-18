import { describe, expect, test } from "bun:test";
import { createHash, createPublicKey } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const ROOT = join(import.meta.dir, "../..");
const VALID_REGISTRY_PATH = join(ROOT, "docs/attestation/measurements.json");
const validRegistry = JSON.parse(readFileSync(VALID_REGISTRY_PATH, "utf8")) as {
  signatures: Array<{ publicKeyPem: string }>;
};
const TRUSTED_FINGERPRINT = createHash("sha256")
  .update(
    createPublicKey(validRegistry.signatures[0]?.publicKeyPem).export({
      format: "der",
      type: "spki",
    }),
  )
  .digest("hex");

function cliEnv(registryPath: string, endpoint: string): Record<string, string | undefined> {
  return {
    ...process.env,
    STEWARD_ATTESTATION_ENDPOINT: endpoint,
    STEWARD_MEASUREMENT_REGISTRY: registryPath,
    STEWARD_REGISTRY_TRUSTED_KEY_SHA256: TRUSTED_FINGERPRINT,
    STEWARD_REGISTRY_ALLOW_UNPINNED: undefined,
  };
}

describe("check-attestation bounded registry ingestion", () => {
  test("rejects a registry file over 4 MiB before JSON parsing or network access", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-attestation-"));
    const registryPath = join(directory, "oversized.json");
    try {
      writeFileSync(registryPath, Buffer.alloc(4 * 1024 * 1024 + 1, 0x20));
      const result = Bun.spawnSync([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(registryPath, "http://127.0.0.1:1/never-requested"),
        stdout: "pipe",
        stderr: "pipe",
      });

      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(
        "measurement registry file exceeded the 4 MiB ingestion limit",
      );
      expect(result.stderr.toString()).not.toContain("fetch");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("rejects malformed registry UTF-8 without exposing parser diagnostics", () => {
    const directory = mkdtempSync(join(tmpdir(), "steward-attestation-"));
    const registryPath = join(directory, "invalid-utf8.json");
    try {
      writeFileSync(registryPath, Uint8Array.from([0x7b, 0xff, 0x7d]));
      const result = Bun.spawnSync([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(registryPath, "http://127.0.0.1:1/never-requested"),
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain(
        "measurement registry file is not valid UTF-8 JSON",
      );
      expect(result.stderr.toString()).not.toContain("SyntaxError");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("cancels a streamed quote response over the decoded byte limit", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => {
        let chunks = 0;
        return new Response(
          new ReadableStream({
            pull(controller) {
              if (chunks >= 17) {
                controller.close();
                return;
              }
              chunks += 1;
              controller.enqueue(new Uint8Array(64 * 1024).fill(0x20));
            },
          }),
        );
      },
    });
    try {
      const processHandle = Bun.spawn([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(VALID_REGISTRY_PATH, `${server.url}quote`),
        stdout: "pipe",
        stderr: "pipe",
      });
      const stderr = await new Response(processHandle.stderr).text();
      expect(await processHandle.exited).not.toBe(0);
      expect(stderr).toContain("quote endpoint response exceeded the 1 MiB limit");
      expect(stderr).not.toContain("padding");
    } finally {
      server.stop(true);
    }
  });

  test("applies the quote cap after gzip decompression", async () => {
    const compressed = gzipSync(new Uint8Array(1024 * 1024 + 1).fill(0x20));
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () =>
        new Response(compressed, {
          headers: { "content-encoding": "gzip", "content-type": "application/json" },
        }),
    });
    try {
      const processHandle = Bun.spawn([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(VALID_REGISTRY_PATH, `${server.url}quote`),
        stdout: "pipe",
        stderr: "pipe",
      });
      const stderr = await new Response(processHandle.stderr).text();
      expect(await processHandle.exited).not.toBe(0);
      expect(stderr).toContain("quote endpoint response exceeded the 1 MiB limit");
    } finally {
      server.stop(true);
    }
  });

  test.each([
    ["URL credentials", "http://user:secret@127.0.0.1:1/quote", "must not contain URL credentials"],
    ["a fragment", "http://127.0.0.1:1/quote#ignored", "must not contain a URL fragment"],
    ["a non-HTTP protocol", "file:///tmp/quote.json", "must use HTTP or HTTPS"],
  ])("rejects an endpoint containing %s before fetch", (_label, endpoint, expected) => {
    const result = Bun.spawnSync([process.execPath, "scripts/check-attestation.ts"], {
      cwd: ROOT,
      env: cliEnv(VALID_REGISTRY_PATH, endpoint),
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(result.exitCode).toBe(2);
    expect(result.stderr.toString()).toContain(expected);
  });

  test("refuses redirects without following them or exposing the destination", async () => {
    let destinationRequests = 0;
    const destination = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => {
        destinationRequests += 1;
        return new Response("should never be reached");
      },
    });
    const redirect = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => Response.redirect(`${destination.url}sensitive-destination`, 302),
    });
    try {
      const processHandle = Bun.spawn([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(VALID_REGISTRY_PATH, `${redirect.url}quote`),
        stdout: "pipe",
        stderr: "pipe",
      });
      const stderr = await new Response(processHandle.stderr).text();
      expect(await processHandle.exited).toBe(1);
      expect(stderr).toContain("quote endpoint request failed");
      expect(stderr).not.toContain("sensitive-destination");
      expect(destinationRequests).toBe(0);
    } finally {
      redirect.stop(true);
      destination.stop(true);
    }
  });

  test("reports only the status for upstream HTTP errors", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => new Response("upstream-secret-token", { status: 401 }),
    });
    try {
      const processHandle = Bun.spawn([process.execPath, "scripts/check-attestation.ts"], {
        cwd: ROOT,
        env: cliEnv(VALID_REGISTRY_PATH, `${server.url}quote`),
        stdout: "pipe",
        stderr: "pipe",
      });
      const stderr = await new Response(processHandle.stderr).text();
      expect(await processHandle.exited).toBe(1);
      expect(stderr).toContain("quote endpoint failed with HTTP 401");
      expect(stderr).not.toContain("upstream-secret-token");
    } finally {
      server.stop(true);
    }
  });
});
