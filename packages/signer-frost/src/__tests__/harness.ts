/**
 * Test harness: build the Rust sidecar (if needed), run trusted-dealer keygen,
 * and spawn N share processes on localhost. Returns endpoints + the group
 * public key + a teardown fn. Used by the E2E FROST tests.
 *
 * Everything here is dev/dummy-key only. Keys are generated fresh per test run
 * into a temp dir and deleted on teardown.
 */

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(__dirname, "..", "..");
const SIDECAR_DIR = join(PKG_ROOT, "sidecar");
const BIN = join(SIDECAR_DIR, "target", "release", "frost-signer");

export interface FrostCluster {
  endpoints: string[];
  /** Per-share bearer tokens the sidecars require (SEC-025). */
  authTokens: string[];
  groupPublicKeyHex: string;
  threshold: number;
  participants: number;
  shareDir: string;
  teardown: () => void;
}

function ensureBinary(): void {
  if (existsSync(BIN)) return;
  const r = spawnSync(
    "cargo",
    ["build", "--release", "--manifest-path", join(SIDECAR_DIR, "Cargo.toml")],
    { stdio: "inherit" },
  );
  if (r.status !== 0) throw new Error("failed to build frost-signer sidecar");
}

async function waitHealthy(url: string, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${url}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`share ${url} did not become healthy in ${timeoutMs}ms`);
}

/** Deterministic-ish free port base to reduce collisions across parallel runs. */
function basePort(): number {
  return 8100 + Math.floor(Math.random() * 400);
}

export async function startFrostCluster(threshold = 2, participants = 3): Promise<FrostCluster> {
  ensureBinary();
  const shareDir = mkdtempSync(join(tmpdir(), "frost-shares-"));

  const kg = spawnSync(
    BIN,
    [
      "keygen",
      "--threshold",
      String(threshold),
      "--participants",
      String(participants),
      "--out",
      shareDir,
    ],
    { encoding: "utf8" },
  );
  if (kg.status !== 0) throw new Error(`keygen failed: ${kg.stderr}`);
  const summary = JSON.parse(kg.stdout) as { group_public_key_hex: string };
  const groupPublicKeyHex = summary.group_public_key_hex;

  // Identifiers are 1..N as 32-byte big-endian hex from the ZF default list.
  const shareFiles: string[] = [];
  for (let i = 1; i <= participants; i++) {
    const idHex = i.toString(16).padStart(64, "0");
    shareFiles.push(join(shareDir, `share-${idHex}.json`));
  }

  const port0 = basePort();
  const endpoints: string[] = [];
  const authTokens: string[] = [];
  const procs: ReturnType<typeof spawn>[] = [];

  for (let i = 0; i < participants; i++) {
    const port = port0 + i;
    const authToken = randomBytes(32).toString("hex");
    const p = spawn(BIN, ["share", "--share-file", shareFiles[i], "--port", String(port)], {
      stdio: "ignore",
      env: { ...process.env, FROST_SHARE_AUTH_TOKEN: authToken },
    });
    procs.push(p);
    endpoints.push(`http://127.0.0.1:${port}`);
    authTokens.push(authToken);
  }

  await Promise.all(endpoints.map((e) => waitHealthy(e)));

  const teardown = () => {
    for (const p of procs) {
      try {
        p.kill("SIGTERM");
      } catch {
        // ignore
      }
    }
    try {
      rmSync(shareDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };

  return { endpoints, authTokens, groupPublicKeyHex, threshold, participants, shareDir, teardown };
}

/** Read the group.json a keygen wrote (used by a sanity assertion in tests). */
export function readGroupFile(shareDir: string): {
  group_public_key_hex: string;
  threshold: number;
  participants: number;
} {
  return JSON.parse(readFileSync(join(shareDir, "group.json"), "utf8"));
}
