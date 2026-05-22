#!/usr/bin/env bun
/**
 * Stand-alone end-to-end auth harness.
 *
 * Boots the fake-oauth-server + Steward API (embedded PGLite, MockEmailProvider,
 * fake-OAuth overrides) and runs cryptographically real SIWE / SIWS verifies,
 * a full magic-link round-trip via the mock email inbox, and the Google +
 * Discord OAuth authorization-code flows. Designed to run without the web app
 * so it can serve as a smoke test in CI before the browser-driven Playwright
 * suite runs.
 *
 * Usage:
 *   bun run scripts/e2e-harness.ts
 *
 * Exit code is non-zero if any flow fails.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import bs58 from "bs58";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const REPO_ROOT = join(__dirname, "..");
const FAKE_PORT = 5598;
const API_PORT = 3298;
const WEB_ORIGIN = `http://localhost:3498`;
const API = `http://localhost:${API_PORT}`;
const FAKE = `http://localhost:${FAKE_PORT}`;
const DATA_DIR = join(tmpdir(), `steward-e2e-harness-${process.pid}`);

mkdirSync(DATA_DIR, { recursive: true });

async function wait(url: string, label: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (r.status < 500) return;
    } catch {
      /* not ready */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${label} not ready at ${url} after ${timeoutMs}ms`);
}

function spawnProc(cmd: string, args: string[], env: Record<string, string>): ChildProcess {
  return spawn(cmd, args, {
    cwd: REPO_ROOT,
    env: { ...process.env, ...env },
    stdio: "inherit",
  });
}

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string): void {
  const tag = cond ? "✅" : "❌";
  console.log(`${tag} ${name}${detail ? ` — ${detail}` : ""}`);
  if (cond) pass++;
  else fail++;
}

async function siweFlow(): Promise<void> {
  const { nonce } = (await (await fetch(`${API}/auth/nonce`)).json()) as { nonce: string };
  const acct = privateKeyToAccount(generatePrivateKey());
  const message = [
    `${new URL(WEB_ORIGIN).host} wants you to sign in with your Ethereum account:`,
    acct.address,
    "",
    "Sign in to Steward",
    "",
    `URI: ${WEB_ORIGIN}`,
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
  const signature = await acct.signMessage({ message });
  const res = await fetch(`${API}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, signature }),
  });
  const body = (await res.json()) as { ok: boolean; token: string; address: string };
  check("SIWE verify (fresh EVM keypair)", res.status === 200 && body.ok === true, body.address);
  check("SIWE returns JWT", body.token?.split(".").length === 3);
}

async function siwsFlow(): Promise<void> {
  const { nonce } = (await (await fetch(`${API}/auth/nonce`)).json()) as { nonce: string };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = spki.subarray(spki.length - 32);
  const address = bs58.encode(rawPub);
  const message = [
    `${new URL(WEB_ORIGIN).host} wants you to sign in with your Solana account:`,
    address,
    "",
    "Sign in to Steward",
    "",
    `URI: ${WEB_ORIGIN}`,
    "Version: 1",
    "Chain ID: mainnet",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
  const sig = cryptoSign(null, Buffer.from(message, "utf8"), privateKey);
  const signature = bs58.encode(sig);
  const res = await fetch(`${API}/auth/verify/solana`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, signature, publicKey: address }),
  });
  const body = (await res.json()) as { ok: boolean; token: string; address: string };
  check(
    "SIWS verify (fresh ed25519 keypair)",
    res.status === 200 && body.ok === true,
    body.address,
  );
  check("SIWS returns JWT", body.token?.split(".").length === 3);
}

async function magicLinkFlow(): Promise<void> {
  const email = `e2e-${Date.now()}@example.test`;
  const sendRes = await fetch(`${API}/auth/email/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  check("Magic link send", sendRes.status === 200);

  const inboxRes = await fetch(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
  const inbox = (await inboxRes.json()) as { token: string; magicLink: string };
  check(
    "Mock inbox returns token",
    inboxRes.status === 200 && /^[a-f0-9]{64}$/.test(inbox.token),
    inbox.token?.slice(0, 12),
  );

  const verifyRes = await fetch(`${API}/auth/email/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: inbox.token, email }),
  });
  const verify = (await verifyRes.json()) as { ok: boolean; token: string };
  check(
    "Magic link redeem mints JWT",
    verifyRes.status === 200 && verify.token?.split(".").length === 3,
  );
}

async function oauthFlow(provider: "google" | "discord"): Promise<void> {
  const email = `${provider}-user-${Date.now()}@example.test`;
  const redirectUri = `${WEB_ORIGIN}/auth/oauth/${provider}/callback`;
  const r1 = await fetch(
    `${API}/auth/oauth/${provider}/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`,
    { redirect: "manual" },
  );
  check(`${provider} /authorize → fake provider`, r1.status === 302);

  const fakeUrl = new URL(r1.headers.get("location") || "");
  fakeUrl.searchParams.set("login_hint", email);
  const r2 = await fetch(fakeUrl.toString(), { redirect: "manual" });
  check(`${provider} fake /authorize → steward /callback`, r2.status === 302);

  const r3 = await fetch(r2.headers.get("location") || "", { redirect: "manual" });
  check(`${provider} /callback → redirect_uri`, r3.status === 302 || r3.status === 303);
  const finalLoc = new URL(r3.headers.get("location") || "");
  const hasToken = finalLoc.searchParams.get("token") || finalLoc.searchParams.get("code");
  check(`${provider} delivers token or code`, !!hasToken);
}

async function main(): Promise<void> {
  const fake = spawnProc("bun", ["run", "scripts/fake-oauth-server.ts"], {
    FAKE_OAUTH_PORT: String(FAKE_PORT),
  });
  const api = spawnProc("bun", ["run", "packages/api/src/embedded.ts"], {
    PORT: String(API_PORT),
    STEWARD_BIND_HOST: "127.0.0.1",
    NODE_ENV: "test",
    STEWARD_PGLITE_PATH: DATA_DIR,
    STEWARD_PGLITE_MEMORY: "true",
    STEWARD_MASTER_PASSWORD: "e2e-master-password-32bytes--okk",
    JWT_SECRET: "e2e-jwt-secret-0000000000000000000000",
    APP_URL: API,
    EMAIL_PROVIDER: "mock",
    GOOGLE_CLIENT_ID: "e2e-google",
    GOOGLE_CLIENT_SECRET: "e2e-google-secret",
    GOOGLE_AUTHORIZATION_URL: `${FAKE}/google/authorize`,
    GOOGLE_TOKEN_URL: `${FAKE}/google/token`,
    GOOGLE_USERINFO_URL: `${FAKE}/google/userinfo`,
    DISCORD_CLIENT_ID: "e2e-discord",
    DISCORD_CLIENT_SECRET: "e2e-discord-secret",
    DISCORD_AUTHORIZATION_URL: `${FAKE}/discord/authorize`,
    DISCORD_TOKEN_URL: `${FAKE}/discord/token`,
    DISCORD_USERINFO_URL: `${FAKE}/discord/userinfo`,
    STEWARD_OAUTH_REDIRECT_ALLOWLIST: `${WEB_ORIGIN},${API}`,
    SIWE_ALLOWED_DOMAINS: `localhost,${new URL(WEB_ORIGIN).host},${new URL(API).host}`,
  });

  const cleanup = () => {
    try {
      api.kill("SIGTERM");
    } catch {}
    try {
      fake.kill("SIGTERM");
    } catch {}
    try {
      rmSync(DATA_DIR, { recursive: true, force: true });
    } catch {}
  };
  process.on("exit", cleanup);

  try {
    await wait(`${FAKE}/`, "fake-oauth-server");
    await wait(`${API}/auth/providers`, "steward api");
    await siweFlow();
    await siwsFlow();
    await magicLinkFlow();
    await oauthFlow("google");
    await oauthFlow("discord");
    console.log(`\n${pass} pass, ${fail} fail`);
  } finally {
    cleanup();
  }
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
