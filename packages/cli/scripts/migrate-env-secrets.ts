#!/usr/bin/env bun
/**
 * migrate-env-secrets — onboard secrets from env-var NAMES (a manifest) into the
 * sealed SecretStore, reading each VALUE from operator input (stdin), never from
 * the process environment or a flag.
 *
 * This is the rehearsal/cutover tool for DSTACK-CANONICAL §4B: it takes a
 * manifest of secret NAMES (what used to live in Railway env vars) and maps each
 * to a store path, then encrypts each value directly to the store recipient. The
 * MANIFEST carries names + target paths ONLY — zero secret material. Values come
 * from the operator, one at a time.
 *
 * SAFETY: rehearse with DUMMY secrets. The live cutover (real Railway creds) is
 * orchestrator-only and NOT run from this script by a lane. This script REFUSES
 * to read values out of process.env by default — that would defeat the whole
 * point (the goal is to get creds OUT of env). Pass --from-env ONLY for a
 * deliberate operator-run migration off a machine that already holds them, and
 * even then it warns loudly.
 *
 * Manifest format (JSON):
 *   {
 *     "secrets": [
 *       { "name": "DISCORD_SOLIZA_TOKEN", "path": "discord/soliza-bot-token", "description": "..." },
 *       { "name": "OPENAI_API_KEY",       "path": "api/openai" }
 *     ]
 *   }
 *
 * Usage:
 *   bun scripts/migrate-env-secrets.ts --manifest secrets.manifest.json --store .steward/secret-store
 *     → prompts for each value on stdin (recommended; values never in env).
 *   bun scripts/migrate-env-secrets.ts --manifest m.json --store S --from-env
 *     → reads each value from process.env[name] (operator-run cutover only).
 *   ... --dry-run   → validate the manifest + report the plan, encrypt nothing.
 */

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { AgeFileSecretStore, sealToRecipient } from "@stwd/vault";

interface ManifestEntry {
  name: string;
  path: string;
  description?: string;
}
interface Manifest {
  secrets: ManifestEntry[];
}

function parseFlags(argv: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  }
  return flags;
}

function loadManifest(path: string): Manifest {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Manifest;
  if (!raw || !Array.isArray(raw.secrets)) {
    throw new Error("manifest must be { secrets: [{ name, path, description? }, ...] }");
  }
  for (const entry of raw.secrets) {
    if (!entry.name || !entry.path) {
      throw new Error(`manifest entry missing name/path: ${JSON.stringify(entry)}`);
    }
    // Guard: a manifest must NEVER carry a value field (would be plaintext at rest).
    if ("value" in (entry as unknown as Record<string, unknown>)) {
      throw new Error(
        `manifest entry for ${entry.name} contains a "value" field — manifests carry NAMES ONLY, never secret values`,
      );
    }
  }
  return raw;
}

async function promptHidden(question: string): Promise<string> {
  // Read one line from stdin. Not true no-echo (that needs a TTY raw mode), but
  // values come line-by-line from the operator, not from env/flags.
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function main(): Promise<void> {
  const flags = parseFlags(Bun.argv.slice(2));
  const manifestPath = typeof flags.manifest === "string" ? flags.manifest : undefined;
  const storeDir = typeof flags.store === "string" ? flags.store : undefined;
  if (!manifestPath || !storeDir) {
    throw new Error(
      "usage: migrate-env-secrets --manifest FILE --store DIR [--from-env] [--dry-run] [--overwrite]",
    );
  }
  const fromEnv = flags["from-env"] === true;
  const dryRun = flags["dry-run"] === true;
  const overwrite = flags.overwrite === true;

  const manifest = loadManifest(manifestPath);
  const store = new AgeFileSecretStore({ storeDir });
  const recipient = await store.recipient();

  if (dryRun) {
    console.log(JSON.stringify({ dryRun: true, recipient, plan: manifest.secrets }, null, 2));
    return;
  }

  if (fromEnv) {
    console.error(
      "WARNING: --from-env reads values from process.env. This is for an operator-run cutover " +
        "on a machine that already holds the creds. Never use it in CI or a lane.",
    );
  }

  const results: Array<{ path: string; version: number; source: string }> = [];
  for (const entry of manifest.secrets) {
    let value: string | undefined;
    let source: string;
    if (fromEnv) {
      value = process.env[entry.name];
      source = `env:${entry.name}`;
      if (!value) {
        console.error(`skip ${entry.name}: not set in environment`);
        continue;
      }
    } else {
      value = await promptHidden(`value for ${entry.name} -> ${entry.path}: `);
      source = "stdin";
      if (!value) {
        console.error(`skip ${entry.name}: empty input`);
        continue;
      }
    }
    const sealed = await sealToRecipient(recipient, value);
    const existing = await store.stat(entry.path);
    const meta = existing
      ? await store.rotateSealed(entry.path, sealed)
      : await store.putSealed(entry.path, sealed, {
          description: entry.description,
          overwrite,
        });
    results.push({ path: meta.path, version: meta.version, source });
    // Drop the reference; do not log the value.
    value = undefined;
    void value;
  }

  console.log(JSON.stringify({ onboarded: results, recipient }, null, 2));
}

main().catch((error) => {
  console.error(`migrate-env-secrets: ${(error as Error).message}`);
  process.exit(1);
});
