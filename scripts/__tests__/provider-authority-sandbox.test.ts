import { afterEach, describe, expect, it } from "bun:test";
import { generateKeyPairSync, verify } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildDispatchEnvironment,
  classifyGithubResponse,
  mintGithubAppJwt,
  mintInstallationToken,
  parseRetryAfter,
  reconcileGithubMarker,
  requestJson,
  scrub,
  validateBuildPrerequisites,
  validateEnvironment,
  validateServiceUrl,
} from "../lib/provider-authority-sandbox-lib.mjs";
import { runDispatchChild } from "../provider-authority-sandbox.mjs";

const servers: Server[] = [];
afterEach(() => servers.splice(0).forEach((server) => server.close()));

async function fakeServer(handler: Parameters<typeof createServer>[0]) {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no test address");
  return `http://127.0.0.1:${address.port}`;
}

function envFixture() {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const env = Object.fromEntries(
    [
      "GITHUB_APP_ID",
      "GITHUB_APP_INSTALLATION_ID",
      "STEWARD_SANDBOX_GITHUB_OWNER",
      "STEWARD_SANDBOX_GITHUB_REPO",
      "STEWARD_SANDBOX_GITHUB_PR_NUMBER",
      "STEWARD_API_URL",
      "STEWARD_TENANT_ID",
      "STEWARD_AGENT_JWT",
      "STEWARD_APPROVER_JWT",
      "STEWARD_SANDBOX_WORKSPACE_ID",
      "STEWARD_SANDBOX_PROVIDER_ACCOUNT_ID",
      "STEWARD_SANDBOX_SECRET_ID",
      "STEWARD_AUDIT_SIGNING_KEY_FINGERPRINT",
      "DATABASE_URL",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_EXECUTION_AUTH_SECRET",
      "STEWARD_AUDIT_HMAC_KEY",
    ]
      .map((key) => [key, `real-${key.toLowerCase()}`])
      .concat([
        ["GITHUB_APP_PRIVATE_KEY", privateKey.export({ format: "pem", type: "pkcs8" }).toString()],
        [
          "STEWARD_AUDIT_SIGNING_KEY",
          "-----BEGIN PRIVATE KEY-----\nnot-a-placeholder\n-----END PRIVATE KEY-----",
        ],
      ]),
  );
  env.STEWARD_API_URL = "https://steward.sandbox.test";
  return env;
}

describe("provider authority sandbox operator primitives", () => {
  it("fails closed and names missing variables without exposing present secrets", () => {
    const env = envFixture();
    const canary = env.STEWARD_AGENT_JWT;
    delete env.DATABASE_URL;
    expect(() => validateEnvironment(env)).toThrow("DATABASE_URL");
    try {
      validateEnvironment(env);
    } catch (error) {
      expect(String(error)).not.toContain(canary);
    }
  });

  it("preflight validation is pure and performs no network", () => {
    let calls = 0;
    const original = globalThis.fetch;
    globalThis.fetch = ((..._args: unknown[]) => {
      calls++;
      throw new Error("network forbidden");
    }) as typeof fetch;
    try {
      validateEnvironment(envFixture());
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toBe(0);
  });

  it("rejects credential-bearing and public plaintext service URLs", () => {
    expect(() => validateServiceUrl("STEWARD_API_URL", "http://api.example.test")).toThrow(
      "must use HTTPS",
    );
    expect(() => validateServiceUrl("GITHUB_API_URL", "https://user:secret@github.test")).toThrow(
      "must not contain credentials",
    );
    expect(() => validateServiceUrl("GITHUB_API_URL", "http://127.0.0.1:3000")).not.toThrow();
  });

  it("bounds declared and streamed HTTP bodies", async () => {
    for (const response of [
      new Response("{}", { headers: { "content-length": "1048577" } }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024));
            controller.enqueue(new Uint8Array([1]));
            controller.close();
          },
        }),
      ),
    ]) {
      await expect(
        requestJson("https://api.example.test", {}, (async () => response) as typeof fetch),
      ).rejects.toThrow("exceeded the 1 MiB sandbox limit");
    }
  });

  it("fails closed with the exact build prerequisite command", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-sandbox-build-"));
    expect(() => validateBuildPrerequisites(root)).toThrow(
      "bunx turbo run build --filter=@stwd/proxy...",
    );
    for (const path of [
      "packages/shared/dist/index.js",
      "packages/redis/dist/index.js",
      "packages/attestation/dist/index.js",
    ]) {
      mkdirSync(join(root, path, ".."), { recursive: true });
      writeFileSync(join(root, path), "export {};\n");
    }
    expect(() => validateBuildPrerequisites(root)).not.toThrow();
  });

  it("mints a signed RS256 GitHub App JWT and exchanges it without logging token", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const jwt = mintGithubAppJwt("42", pem, 1_800_000_000);
    const [head, body, signature] = jwt.split(".");
    expect(JSON.parse(Buffer.from(head, "base64url").toString())).toEqual({
      alg: "RS256",
      typ: "JWT",
    });
    expect(JSON.parse(Buffer.from(body, "base64url").toString()).iss).toBe("42");
    expect(
      verify(
        "RSA-SHA256",
        Buffer.from(`${head}.${body}`),
        publicKey,
        Buffer.from(signature, "base64url"),
      ),
    ).toBe(true);

    const canary = "ghs_NEVER_WRITE_THIS_TOKEN";
    const base = await fakeServer((request, response) => {
      expect(request.method).toBe("POST");
      expect(request.headers.authorization).toStartWith("Bearer ey");
      response.writeHead(201, { "content-type": "application/json" });
      response.end(JSON.stringify({ token: canary }));
    });
    expect(
      await mintInstallationToken({
        GITHUB_APP_ID: "42",
        GITHUB_APP_INSTALLATION_ID: "7",
        GITHUB_APP_PRIVATE_KEY: pem,
        GITHUB_API_URL: base,
      }),
    ).toBe(canary);
    expect(scrub({ authorization: `Bearer ${canary}`, token: canary }, [canary])).not.toContain(
      canary,
    );
  });

  it("finds a marker across bounded pagination and reports a bounded miss", async () => {
    let calls = 0;
    const base = await fakeServer((_request, response) => {
      calls++;
      response.writeHead(200, { "content-type": "application/json" });
      const rows =
        calls === 1
          ? Array.from({ length: 100 }, (_, id) => ({ id, body: "other" }))
          : [{ id: 999, body: "marker-123" }];
      response.end(JSON.stringify(rows));
    });
    const found = await reconcileGithubMarker({
      apiBase: base,
      owner: "o",
      repo: "r",
      pullNumber: 1,
      marker: "marker-123",
      token: "secret",
      maxAttempts: 1,
      maxPages: 2,
    });
    expect(found.outcome).toBe("found");
    expect(found.requests).toBe(2);

    const missBase = await fakeServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("[]");
    });
    const miss = await reconcileGithubMarker({
      apiBase: missBase,
      owner: "o",
      repo: "r",
      pullNumber: 1,
      marker: "absent",
      token: "secret",
      maxAttempts: 2,
      maxPages: 3,
      sleep: async () => {},
    });
    expect(miss.outcome).toBe("definitive_miss");
    expect(miss.requests).toBe(2);
  });

  it("classifies 403/429 and caps Retry-After", async () => {
    expect(classifyGithubResponse(403, new Headers({ "retry-after": "99" })).classification).toBe(
      "rate_limited",
    );
    expect(classifyGithubResponse(403).classification).toBe("request_failure");
    expect(classifyGithubResponse(429).boundedFailure).toBe(true);
    expect(parseRetryAfter("99", 1500)).toBe(1500);
    const waits: number[] = [];
    const result = await reconcileGithubMarker({
      owner: "o",
      repo: "r",
      pullNumber: 1,
      marker: "m",
      token: "secret",
      maxAttempts: 2,
      retryAfterCapMs: 7,
      fetchImpl: async () => new Response("{}", { status: 429, headers: { "retry-after": "100" } }),
      sleep: async (ms) => {
        waits.push(ms);
      },
    });
    expect(result.outcome).toBe("indeterminate");
    expect(result.requests).toBe(2);
    expect(Math.max(...waits)).toBeLessThanOrEqual(7);
  });

  it("kills only after the child proves it crossed the upstream barrier", async () => {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: (signal: string) => void;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = (signal) => child.emit("close", null, signal);
    const spawnImpl = () => {
      setTimeout(() => child.stdout.emit("data", Buffer.from('{"phase":"after_upstream"}\n')), 1);
      return child;
    };
    const result = await runDispatchChild({ STEWARD_TENANT_ID: "tenant" }, "intent", {
      pauseAfterUpstream: true,
      timeoutMs: 1,
      spawnImpl,
    });
    expect(result.reachedAfterUpstream).toBe(true);
    expect(result.timedOut).toBe(true);
  });

  it("scrubs tokens, authorization values, and PEM blocks from every surface", () => {
    const token = "ghs_CANARY_NOT_FOR_ARTIFACTS";
    const pem = "-----BEGIN PRIVATE KEY-----\nCANARY_PRIVATE\n-----END PRIVATE KEY-----";
    const output = scrub({ stdout: `Bearer ${token}`, stderr: token, artifact: pem }, [token, pem]);
    expect(output).not.toContain(token);
    expect(output).not.toContain("CANARY_PRIVATE");
    expect(output).toContain("[REDACTED]");
  });

  it("does not pass GitHub credentials or API JWTs to the dispatch child", () => {
    const childEnv = buildDispatchEnvironment(
      {
        PATH: "/bin",
        DATABASE_URL: "postgres://db",
        STEWARD_MASTER_PASSWORD: "master",
        STEWARD_EXECUTION_AUTH_SECRET: "execution",
        GITHUB_APP_PRIVATE_KEY: "private-canary",
        STEWARD_AGENT_JWT: "agent-canary",
        STEWARD_APPROVER_JWT: "approver-canary",
      },
      true,
    );
    expect(childEnv.DATABASE_URL).toBe("postgres://db");
    expect(childEnv.STEWARD_EXECUTION_AUTH_SECRET).toBe("execution");
    expect(JSON.stringify(childEnv)).not.toContain("canary");
    expect(childEnv.STEWARD_SANDBOX_AFTER_UPSTREAM_PAUSE_MS).toBe("30000");
  });
});
