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
  isLiveRateLimitObservation,
  mintGithubAppJwt,
  mintInstallationCredential,
  parseRetryAfter,
  reconcileGithubMarker,
  requestJson,
  revokeInstallationToken,
  scrub,
  validateBuildPrerequisites,
  validateEnvironment,
  validateServiceUrl,
  verifyInstallationScope,
} from "../lib/provider-authority-sandbox-lib.mjs";
import {
  prepareApprovedWrite,
  requireRawCaseManifest,
  runDispatchChild,
} from "../provider-authority-sandbox.mjs";

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
      "STEWARD_KDF_SALT",
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
  env.STEWARD_KDF_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
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

  it("fails closed when the live vault KDF salt is missing or malformed", () => {
    // RSA fixture generation is intentionally expensive. Generate it once so
    // this validation table stays within Bun's default per-test timeout (the
    // official scripts/__tests__ CI command does not raise that timeout).
    const valid = envFixture();

    const missing = { ...valid };
    delete missing.STEWARD_KDF_SALT;
    expect(() => validateEnvironment(missing)).toThrow("STEWARD_KDF_SALT");

    const short = { ...valid, STEWARD_KDF_SALT: "abcd" };
    expect(() => validateEnvironment(short)).toThrow("at least 32 characters");

    const nonHex = { ...valid, STEWARD_KDF_SALT: `${"a".repeat(32)}zz` };
    expect(() => validateEnvironment(nonHex)).toThrow("even-length hexadecimal string");

    const oddLength = { ...valid, STEWARD_KDF_SALT: "a".repeat(33) };
    expect(() => validateEnvironment(oddLength)).toThrow("even-length hexadecimal string");

    const trailingSpace = { ...valid, STEWARD_KDF_SALT: `${"a".repeat(32)} ` };
    expect(() => validateEnvironment(trailingSpace)).toThrow("even-length hexadecimal string");

    const uppercase = { ...valid, STEWARD_KDF_SALT: "AB".repeat(16) };
    expect(() => validateEnvironment(uppercase)).not.toThrow();
  });

  it("rejects credential-bearing and public plaintext service URLs", async () => {
    expect(() => validateServiceUrl("STEWARD_API_URL", "http://api.example.test")).toThrow(
      "must use HTTPS",
    );
    expect(() => validateServiceUrl("GITHUB_API_URL", "https://user:secret@github.test")).toThrow(
      "must not contain credentials",
    );
    expect(() => validateServiceUrl("GITHUB_API_URL", "http://127.0.0.1:3000")).not.toThrow();
    await expect(
      reconcileGithubMarker({
        apiBase: "http://api.example.test",
        owner: "o",
        repo: "r",
        pullNumber: 1,
        marker: "m",
        token: "secret",
      }),
    ).rejects.toThrow("must use HTTPS");
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

  it("disables HTTP redirects before credential-bearing fetches", async () => {
    let redirectMode: RequestRedirect | undefined;
    await requestJson("https://api.example.test", {}, (async (_url, options) => {
      redirectMode = options?.redirect;
      return new Response("{}");
    }) as typeof fetch);
    expect(redirectMode).toBe("error");
  });

  it("rejects an actual redirect without contacting its destination", async () => {
    let destinationCalls = 0;
    const base = await fakeServer((request, response) => {
      if (request.url === "/destination") destinationCalls++;
      if (request.url === "/redirect") {
        response.writeHead(302, { location: `${base}/destination` });
        response.end();
        return;
      }
      response.end("{}");
    });
    await expect(
      requestJson(`${base}/redirect`, {}, fetch, { expectedOrigin: base }),
    ).rejects.toThrow();
    expect(destinationCalls).toBe(0);
  });

  it("enforces its own deadline even when the caller supplies a non-aborting signal", async () => {
    const base = await fakeServer((_request, _response) => {
      // Intentionally never respond; requestJson's deadline must abort this.
    });
    await expect(
      requestJson(`${base}/slow`, { signal: new AbortController().signal }, fetch, {
        expectedOrigin: base,
        timeoutMs: 20,
      }),
    ).rejects.toThrow();
  });

  it("pins the request origin before sending credentials", async () => {
    let calls = 0;
    await expect(
      requestJson(
        "https://attacker.example/token",
        { headers: { authorization: "Bearer canary" } },
        (async () => {
          calls++;
          return new Response("{}");
        }) as typeof fetch,
        { expectedOrigin: "https://api.github.com" },
      ),
    ).rejects.toThrow("origin mismatch");
    expect(calls).toBe(0);
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
      response.end(
        JSON.stringify({
          token: canary,
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          permissions: { metadata: "read", issues: "write" },
          repository_selection: "selected",
        }),
      );
    });
    const credential = await mintInstallationCredential({
      GITHUB_APP_ID: "42",
      GITHUB_APP_INSTALLATION_ID: "7",
      GITHUB_APP_PRIVATE_KEY: pem,
      GITHUB_API_URL: base,
    });
    expect(credential.token).toBe(canary);
    expect(credential.permissions).toEqual({ metadata: "read", issues: "write" });
    expect(scrub({ authorization: `Bearer ${canary}`, token: canary }, [canary])).not.toContain(
      canary,
    );

    let revokedAuthorization = "";
    await revokeInstallationToken(canary, async (_url, options) => {
      revokedAuthorization = new Headers(options?.headers).get("authorization") ?? "";
      return new Response(null, { status: 204 });
    });
    expect(revokedAuthorization).toBe(`Bearer ${canary}`);
  });

  it("rejects API redirection and verifies exact App permissions and repository scope", async () => {
    const env = envFixture();
    env.GITHUB_API_URL = "https://attacker.example";
    expect(() => validateEnvironment(env)).toThrow("https://api.github.com");

    const base = await fakeServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          total_count: 1,
          repositories: [{ full_name: "sandbox-owner/sandbox-repo" }],
        }),
      );
    });
    await expect(
      verifyInstallationScope(
        {
          token: "token",
          permissions: { metadata: "read", issues: "write" },
          repositorySelection: "selected",
        },
        { owner: "sandbox-owner", repo: "sandbox-repo", apiBase: base },
      ),
    ).resolves.toBeUndefined();
    await expect(
      verifyInstallationScope(
        {
          token: "ghs_SCOPE_CANARY_MUST_NOT_LEAK",
          permissions: { metadata: "read", issues: "write", contents: "read" },
          repositorySelection: "selected",
        },
        { owner: "sandbox-owner", repo: "sandbox-repo", apiBase: base },
      ),
    ).rejects.toThrow("permissions");
    try {
      await verifyInstallationScope(
        {
          token: "ghs_SCOPE_CANARY_MUST_NOT_LEAK",
          permissions: { metadata: "read" },
          repositorySelection: "selected",
        },
        { owner: "sandbox-owner", repo: "sandbox-repo", apiBase: base },
      );
    } catch (error) {
      expect(String(error)).not.toContain("ghs_SCOPE_CANARY_MUST_NOT_LEAK");
    }
  });

  it("uses the no-body execute contract and accepts the live raw case shape", async () => {
    const calls: Array<{ path: string; options: RequestInit }> = [];
    const stewardImpl = async (
      _env: Record<string, string>,
      path: string,
      _token: string,
      options: RequestInit = {},
    ) => {
      calls.push({ path, options });
      if (path === "/v2/provider-actions") {
        return {
          id: "pa_test",
          status: "pending_approval",
          requestHash: `sha256:${"a".repeat(64)}`,
          actionDigest: `sha256:${"b".repeat(64)}`,
        };
      }
      if (path.endsWith("/approval") && options.method !== "POST") {
        return { data: { version: 1 } };
      }
      if (path.endsWith("/execute")) return { status: "execution_ready" };
      return { status: "approved" };
    };
    await prepareApprovedWrite(envFixture(), "marker", "body", stewardImpl);
    const execute = calls.find((call) => call.path.endsWith("/execute"));
    expect(execute?.options).toEqual({ method: "POST" });
    expect(execute?.options.body).toBeUndefined();

    const raw = { schemaVersion: "steward.provider-case-manifest.v1", caseId: "pa_test" };
    expect(requireRawCaseManifest(raw, "pa_test")).toBe(raw);
    expect(() => requireRawCaseManifest({ manifest: raw }, "pa_test")).toThrow(
      "expected case manifest",
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

    const truncated = await reconcileGithubMarker({
      owner: "o",
      repo: "r",
      pullNumber: 1,
      marker: "absent",
      token: "secret",
      maxAttempts: 1,
      maxPages: 1,
      fetchImpl: async () =>
        Response.json(Array.from({ length: 100 }, (_, id) => ({ id, body: "other" }))),
    });
    expect(truncated.outcome).toBe("indeterminate");
    expect(truncated.classification.classification).toBe("pagination_bound_exhausted");
  });

  it("classifies 403/429 and caps Retry-After", async () => {
    expect(classifyGithubResponse(403, new Headers({ "retry-after": "99" })).classification).toBe(
      "rate_limited",
    );
    expect(classifyGithubResponse(403).classification).toBe("request_failure");
    expect(classifyGithubResponse(429).boundedFailure).toBe(true);
    expect(
      isLiveRateLimitObservation({
        status: 403,
        classification: "request_failure",
        retryAfter: null,
      }),
    ).toBe(false);
    expect(
      isLiveRateLimitObservation({
        status: 429,
        classification: "rate_limited",
        retryAfter: "1",
      }),
    ).toBe(true);
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
    expect(result.outputExceeded).toBe(false);
  });

  it("fails the child result closed when output exceeds one MiB", async () => {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: (signal: string) => void;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = (signal) => child.emit("close", null, signal);
    const spawnImpl = () => {
      setTimeout(() => child.stderr.emit("data", Buffer.alloc(1024 * 1024 + 1)), 1);
      return child;
    };
    const result = await runDispatchChild({ STEWARD_TENANT_ID: "tenant" }, "intent", { spawnImpl });
    expect(result.outputExceeded).toBe(true);
    expect(result.timedOut).toBe(false);
  });

  it("records child spawn errors without copying the OS error text", async () => {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: (signal: string) => void;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};
    const spawnImpl = () => {
      setTimeout(() => {
        child.emit("error", new Error("CANARY_OS_ERROR"));
        child.emit("close", -2, null);
      }, 1);
      return child;
    };
    const result = await runDispatchChild({ STEWARD_TENANT_ID: "tenant" }, "intent", { spawnImpl });
    expect(result.spawnError).toBe(true);
    expect(JSON.stringify(result)).not.toContain("CANARY_OS_ERROR");
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
