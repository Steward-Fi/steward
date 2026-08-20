import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { redactForDisplay, redactSensitiveText, sanitizeTerminalText } from "../format";

const CLI_ENTRY = join(dirname(dirname(fileURLToPath(import.meta.url))), "index.ts");
const TOKEN = "agent-secret-token-value";
let server: ReturnType<typeof Bun.serve>;
let hits = 0;

async function runCli(args: string[]) {
  const proc = Bun.spawn(["bun", CLI_ENTRY, ...args], { stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    fetch(request) {
      hits += 1;
      if (new URL(request.url).pathname === "/agents/agent-a/token") {
        return Response.json({
          ok: true,
          data: {
            token: TOKEN,
            agentId: "agent-a",
            tenantId: "tenant-a",
            scope: "agent",
            scopes: ["agent"],
            expiresIn: "24h",
          },
        });
      }
      return Response.json({ error: `bad\u001b[2J\nforged bearer-token-value` }, { status: 400 });
    },
  });
});

afterAll(() => server.stop(true));

describe("CLI secret and terminal output boundary", () => {
  test("terminal text escapes control characters and exact secrets", () => {
    expect(sanitizeTerminalText("bad\u001b[2J\nforged")).toBe("bad\\u001b[2J\\u000aforged");
    expect(redactSensitiveText("failed bearer-token-value", ["bearer-token-value"])).toBe(
      "failed [REDACTED]",
    );
    expect(
      redactForDisplay({
        token: "agent-token",
        nested: { refreshToken: "refresh", secretId: "non-secret-id", publicKey: "public" },
      }),
    ).toEqual({
      token: "[REDACTED]",
      nested: { refreshToken: "[REDACTED]", secretId: "non-secret-id", publicKey: "public" },
    });
  });

  test("agent tokens go to an owner-only file and never stdout by default", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-token-output-"));
    try {
      const out = join(dir, "token.json");
      const result = await runCli([
        "agent",
        "token",
        "--agent-id",
        "agent-a",
        "--api-url",
        `http://127.0.0.1:${server.port}`,
        "--tenant-key",
        "tenant-key-value",
        "--out",
        out,
      ]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toContain(TOKEN);
      expect(result.stdout).toContain("[REDACTED]");
      expect(readFileSync(out, "utf8")).toContain(TOKEN);
      expect(statSync(out).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("missing token output destination fails before minting", async () => {
    const before = hits;
    const result = await runCli([
      "agent",
      "token",
      "--agent-id",
      "agent-a",
      "--api-url",
      `http://127.0.0.1:${server.port}`,
      "--tenant-key",
      "tenant-key-value",
    ]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("requires --out");
    expect(hits).toBe(before);
  });

  test("API errors redact configured tokens and cannot inject terminal lines", async () => {
    const result = await runCli([
      "agent",
      "list",
      "--api-url",
      `http://127.0.0.1:${server.port}`,
      "--token",
      "bearer-token-value",
    ]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).not.toContain("bearer-token-value");
    expect(result.stderr).not.toContain("\u001b");
    expect(result.stderr).toContain("\\u001b[2J\\u000aforged [REDACTED]");
  });
});
