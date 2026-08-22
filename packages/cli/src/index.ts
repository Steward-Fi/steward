#!/usr/bin/env bun

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  fchmodSync,
  constants as fsConstants,
  fstatSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { StewardApiClient } from "./api";
import { boolFlag, intFlag, parseArgs, parseJsonFlag, required, stringFlag } from "./args";
import { runDoctor } from "./doctor";
import {
  type OutputFormat,
  printResult,
  redactSensitiveText,
  sanitizeTerminalText,
} from "./format";
import { runInit } from "./init";

type CommandContext = {
  api: StewardApiClient;
  flags: Record<string, string | boolean>;
  format: OutputFormat;
};

type ArchiveChunkReference = {
  index: number;
  file: string;
  sha256?: string;
  byteLength?: number;
};

const MAX_ARCHIVE_CHUNKS = 2_048;
const MAX_ARCHIVE_MANIFEST_BYTES = 768 * 1024;
const MAX_ARCHIVE_ENVELOPE_BYTES = 1024 * 1024;

/** Write sensitive output without following symlinks and make an existing
 * permissive file owner-only before any secret bytes are written. */
export function writeOwnerOnlyFile(path: string, contents: string): void {
  const fd = openOwnerOnlyFile(path);
  try {
    writeOwnerOnlyFileDescriptor(fd, contents);
  } finally {
    closeSync(fd);
  }
}

function openOwnerOnlyFile(path: string): number {
  const fd = openSync(
    path,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    0o600,
  );
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new Error(`Sensitive output is not a regular file: ${path}`);
    }
    if (stat.nlink !== 1) {
      throw new Error(`Sensitive output must not be hard-linked: ${path}`);
    }
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error(`Sensitive output is not owned by the current user: ${path}`);
    }
    // The open() mode is creation-only. Tighten reused output before writing.
    fchmodSync(fd, 0o600);
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function writeOwnerOnlyFileDescriptor(fd: number, contents: string): void {
  // Truncate only after all inode checks and the permission change. O_TRUNC
  // would destroy a special/hard-linked target before it could be rejected.
  ftruncateSync(fd, 0);
  writeFileSync(fd, contents, { encoding: "utf8" });
}

/** Read an untrusted archive file without following symlinks, blocking on
 * special files, or allocating beyond its validated size. */
export function readBoundedRegularFile(
  path: string,
  maxBytes: number,
  expectedBytes?: number,
): Buffer {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`Archive input is not a regular file: ${path}`);
    if (!Number.isSafeInteger(stat.size) || stat.size < 1 || stat.size > maxBytes) {
      throw new Error(`Archive input exceeds the ${maxBytes} byte limit: ${path}`);
    }
    if (expectedBytes !== undefined && stat.size !== expectedBytes) {
      throw new Error(`Archive input size does not match the signed manifest: ${path}`);
    }
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    const extra = Buffer.alloc(1);
    if (offset !== bytes.length || readSync(fd, extra, 0, 1, offset) !== 0) {
      throw new Error(`Archive input changed while it was being read: ${path}`);
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

export function assertSafeArchiveChunks(
  chunks: unknown,
  requireIntegrityFields = false,
): asserts chunks is ArchiveChunkReference[] {
  if (!Array.isArray(chunks) || chunks.length === 0 || chunks.length > MAX_ARCHIVE_CHUNKS) {
    throw new Error("Archive manifest has an invalid chunk list");
  }
  for (let index = 0; index < chunks.length; index++) {
    const chunk = chunks[index] as Partial<ArchiveChunkReference> | null;
    const expectedFile = `chunk-${String(index).padStart(6, "0")}.jsonl`;
    if (
      !chunk ||
      chunk.index !== index ||
      chunk.file !== expectedFile ||
      (requireIntegrityFields && (chunk.sha256 === undefined || chunk.byteLength === undefined)) ||
      (chunk.sha256 !== undefined && !/^[0-9a-f]{64}$/.test(chunk.sha256)) ||
      (chunk.byteLength !== undefined &&
        (!Number.isSafeInteger(chunk.byteLength) ||
          chunk.byteLength < 1 ||
          chunk.byteLength > 1024 * 1024))
    ) {
      throw new Error(`Archive manifest chunk ${index} is invalid or unsafe`);
    }
  }
}

export function assertSafeArchiveManifestTransport(manifest: unknown): void {
  const encoded = new TextEncoder().encode(JSON.stringify(manifest));
  if (encoded.length > MAX_ARCHIVE_MANIFEST_BYTES) {
    throw new Error("Archive manifest exceeds the safe API transport limit");
  }
}

export type AuditArchiveVerificationMode = "none" | "trusted" | "integrity-only";

/** A signature checked only against the key shipped in the same envelope
 * proves self-consistency, not the identity of the signer. */
export function auditArchiveVerificationMode(flags: Record<string, string | boolean>): {
  mode: AuditArchiveVerificationMode;
  fingerprint?: string;
  keyId?: string;
} {
  const verifyTrusted = boolFlag(flags, "verify");
  const integrityOnly = boolFlag(flags, "integrity-only");
  const fingerprint = stringFlag(flags, "fp");
  const keyId = stringFlag(flags, "key-id");
  if (verifyTrusted && integrityOnly) {
    throw new Error("--verify and --integrity-only are mutually exclusive");
  }
  if (verifyTrusted && !fingerprint) {
    throw new Error("--verify requires --fp from an independent trusted channel");
  }
  if (integrityOnly && fingerprint) {
    throw new Error("Use --verify with --fp for trusted verification");
  }
  if (!verifyTrusted && (fingerprint || keyId)) {
    throw new Error("--fp and --key-id require --verify");
  }
  if (fingerprint && !/^[0-9a-f]{64}$/i.test(fingerprint)) {
    throw new Error("--fp must be exactly 64 hexadecimal characters");
  }
  if (keyId && !/^[A-Za-z0-9_.:-]{1,64}$/.test(keyId)) {
    throw new Error("--key-id is invalid");
  }
  if (verifyTrusted) return { mode: "trusted", fingerprint, keyId };
  if (integrityOnly) return { mode: "integrity-only", keyId };
  return { mode: "none" };
}

/**
 * Absolute path to the offline evidence-bundle verifier SHIPPED WITH the CLI.
 * Resolved against the CLI's own location (never the operator's CWD, which may
 * be an attacker-writable directory containing a decoy
 * `scripts/verify-evidence-bundle.mjs`) and executed via process.execPath so
 * the runtime is the same one running the CLI.
 */
export function evidenceBundleVerifierScript(): string {
  return join(import.meta.dir, "../../../scripts/verify-evidence-bundle.mjs");
}

const HELP = `steward CLI

Usage:
  steward init [--env .env] [--force] [--migrate]
  steward doctor [--strict] [--json]
  steward tenant create --id ID --name NAME [--api-key-file F] [--api-key-env VAR]
                        (key via stdin/--api-key-file/--api-key-env preferred; --api-key warns)
  steward agent create --name NAME [--id ID]
  steward agent token --agent-id ID --out token.json [--expires-in 24h] [--scopes agent,api:proxy]
                      [--show-token]  # explicit unsafe terminal compatibility mode
  steward secret add --name NAME [--file F] [--description TEXT]   (value via stdin or --file preferred; --value warns)
  steward secret rotate --id ID [--file F]                          (value via stdin or --file preferred; --value warns)
  steward route add --secret-id ID --agent-id ID --host HOST --path PATH --method METHOD --inject-as header --inject-key KEY
  steward policy set --name NAME --rules '[...]' [--description TEXT] [--agent-id ID]
  steward approvals list|stats|approve|deny ...
  steward audit bundle [--from 1] [--to N] [--out bundle.json] [--verify]
  steward audit export --from N --to N --out DIR [--chunk-size N] [--verify --fp HEX] [--key-id ID]
                       [--integrity-only]
  steward audit list [--limit N] [--before ISO_TIMESTAMP]
  steward audit restore --in DIR
  steward audit acknowledge --archive-id ID --file signed-ack.json
  steward provider-action create --workspace-id ID --account-id ID --operation KEY --arguments '{...}' --idempotency-key KEY
  steward provider-action get|approval|case --id ID
  steward provider-action approve|deny --id ID --reason TEXT [--idempotency-key KEY]
  steward provider-action execute --id ID [--idempotency-key KEY]
  steward provider-action evidence --id ID [--out bundle.json] [--verify --fp HEX]

provider-action commands are thin wrappers over the governed routes
(convenience only; the authoritative proof is
scripts/provider-authority-golden-path.mjs). No new authority is introduced.

Auth:
  --api-url, --tenant-id, --token, --tenant-key, and --platform-key override
  STEWARD_* env vars (STEWARD_API_URL, STEWARD_TENANT_ID, STEWARD_TOKEN,
  STEWARD_TENANT_KEY, STEWARD_PLATFORM_KEY).
  Tenant creation uses X-Steward-Platform-Key.
  Other API-backed commands prefer a Bearer --token; if none is set they fall
  back to the tenant API key (--tenant-key -> X-Steward-Key), which the API
  treats as an api-key machine credential. This is the non-interactive path the
  golden-path script uses (api-key auth bypasses the human-session MFA step-up).
  doctor --strict additionally verifies /audit/integrity and therefore requires
  an owner/admin Bearer session with recent MFA; tenant keys and agent tokens
  intentionally fail that check.
`;

function createContext(flags: Record<string, string | boolean>): CommandContext {
  return {
    api: new StewardApiClient({
      baseUrl: stringFlag(flags, "api-url"),
      tenantId: stringFlag(flags, "tenant-id"),
      token: stringFlag(flags, "token"),
      platformKey: stringFlag(flags, "platform-key"),
      tenantKey: stringFlag(flags, "tenant-key"),
    }),
    flags,
    format: boolFlag(flags, "json") ? "json" : "pretty",
  };
}

async function tenantCommand(action: string | undefined, ctx: CommandContext) {
  if (action !== "create") throw new Error("Supported tenant command: tenant create");
  const apiKey = readTenantApiKey(ctx.flags);
  const body = {
    id: required(stringFlag(ctx.flags, "id"), "id"),
    name: required(stringFlag(ctx.flags, "name"), "name"),
    apiKeyHash: apiKey,
  };
  return ctx.api.request("POST", "/tenants", body, { platform: true, tenant: false });
}

async function agentCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "create") {
    return ctx.api.request("POST", "/agents", {
      id: stringFlag(ctx.flags, "id"),
      name: required(stringFlag(ctx.flags, "name"), "name"),
      platformId: stringFlag(ctx.flags, "platform-id"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/agents");
  if (action === "token") {
    const agentId = required(stringFlag(ctx.flags, "agent-id"), "agent-id");
    const out = stringFlag(ctx.flags, "out");
    const showToken = boolFlag(ctx.flags, "show-token");
    if (!out && !showToken) {
      throw new Error(
        "agent token output requires --out <owner-only-file>; use --show-token only when terminal/log capture is disabled",
      );
    }
    // Open, validate, and permission the destination before minting, then keep
    // this exact inode open across the request. That closes the path-swap race
    // that could otherwise orphan a live token after a successful response.
    const outFd = out ? openOwnerOnlyFile(out) : undefined;
    const scopes = stringFlag(ctx.flags, "scopes")
      ?.split(",")
      .map((scope) => scope.trim())
      .filter(Boolean);
    try {
      const result = await ctx.api.request<Record<string, unknown> & { token: string }>(
        "POST",
        `/agents/${encodeURIComponent(agentId)}/token`,
        {
          expiresIn: stringFlag(ctx.flags, "expires-in"),
          scopes,
        },
      );
      if (typeof result.token !== "string" || result.token.length === 0) {
        throw new Error("Steward returned an invalid agent token response");
      }
      if (outFd !== undefined && out) {
        writeOwnerOnlyFileDescriptor(outFd, `${JSON.stringify(result, null, 2)}\n`);
        const { token: _token, ...receipt } = result;
        return { ...receipt, token: "[REDACTED]", wrote: out };
      }
      console.error(
        "[steward] WARNING: --show-token writes a bearer credential to stdout; disable terminal and CI log capture",
      );
      return result;
    } finally {
      if (outFd !== undefined) closeSync(outFd);
    }
  }
  throw new Error("Supported agent commands: agent create|list|token");
}

/**
 * Read a secret value for onboarding/rotation. Preferred sources are --file or
 * stdin so the plaintext never lands in shell history or `ps` output. --value
 * remains for backward compatibility but warns loudly (salvaged from the
 * sovereign-custody path: zero-plaintext-transit onboarding).
 */
export function readSecretValue(flags: Record<string, string | boolean>): string {
  const file = stringFlag(flags, "file");
  if (file) {
    // Strip a single trailing newline (editors add one) but keep interior bytes.
    return readFileSync(file, "utf8").replace(/\n$/, "");
  }
  const flagValue = stringFlag(flags, "value");
  if (flagValue !== undefined) {
    console.error(
      "[steward] WARNING: --value places the secret in shell history and process listings. " +
        'Prefer --file <path> or stdin: printf %s "$SECRET" | steward secret add --name NAME',
    );
    return flagValue;
  }
  if (!process.stdin.isTTY) {
    const data = readFileSync(0, "utf8").replace(/\n$/, "");
    if (data) return data;
  }
  throw new Error(
    "secret value required: pipe it on stdin, pass --file <path>, or (discouraged) --value",
  );
}

/**
 * Read the tenant API key for `tenant create`. Preferred sources are
 * --api-key-file, --api-key-env, or stdin so the plaintext credential never
 * lands in shell history or `ps` output. --api-key remains for backward
 * compatibility but warns loudly (same treatment as readSecretValue above).
 */
export function readTenantApiKey(flags: Record<string, string | boolean>): string {
  const file = stringFlag(flags, "api-key-file");
  if (file) {
    // Strip a single trailing newline (editors add one) but keep interior bytes.
    return readFileSync(file, "utf8").replace(/\n$/, "");
  }
  const envVar = stringFlag(flags, "api-key-env");
  if (envVar) {
    const value = process.env[envVar];
    if (value) return value;
    throw new Error(`--api-key-env: environment variable '${envVar}' is unset or empty`);
  }
  const flagValue = stringFlag(flags, "api-key");
  if (flagValue !== undefined) {
    console.error(
      "[steward] WARNING: --api-key places the credential in shell history and process listings. " +
        "Prefer --api-key-file <path>, --api-key-env <VAR>, or stdin: " +
        'printf %s "$KEY" | steward tenant create --id ID --name NAME',
    );
    return flagValue;
  }
  if (!process.stdin.isTTY) {
    const data = readFileSync(0, "utf8").replace(/\n$/, "");
    if (data) return data;
  }
  throw new Error(
    "tenant API key required: pipe it on stdin, pass --api-key-file <path>, " +
      "--api-key-env <VAR>, or (discouraged) --api-key",
  );
}

async function secretCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "add") {
    return ctx.api.request("POST", "/secrets", {
      name: required(stringFlag(ctx.flags, "name"), "name"),
      value: readSecretValue(ctx.flags),
      description: stringFlag(ctx.flags, "description"),
      expiresAt: stringFlag(ctx.flags, "expires-at"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/secrets");
  if (action === "rotate") {
    const id = required(stringFlag(ctx.flags, "id"), "id");
    return ctx.api.request("PUT", `/secrets/${encodeURIComponent(id)}`, {
      value: readSecretValue(ctx.flags),
    });
  }
  throw new Error("Supported secret commands: secret add|list|rotate");
}

async function routeCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "add") {
    return ctx.api.request("POST", "/secrets/routes", {
      secretId: required(stringFlag(ctx.flags, "secret-id"), "secret-id"),
      agentId: required(stringFlag(ctx.flags, "agent-id"), "agent-id"),
      hostPattern: required(stringFlag(ctx.flags, "host"), "host"),
      pathPattern: required(stringFlag(ctx.flags, "path"), "path"),
      method: required(stringFlag(ctx.flags, "method"), "method"),
      injectAs: required(stringFlag(ctx.flags, "inject-as"), "inject-as"),
      injectKey: required(stringFlag(ctx.flags, "inject-key"), "inject-key"),
      injectFormat: stringFlag(ctx.flags, "inject-format"),
      priority: intFlag(ctx.flags, "priority"),
      enabled: ctx.flags.enabled === undefined ? undefined : boolFlag(ctx.flags, "enabled"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/secrets/routes");
  if (action === "delete") {
    const id = required(stringFlag(ctx.flags, "id"), "id");
    return ctx.api.request("DELETE", `/secrets/routes/${encodeURIComponent(id)}`);
  }
  throw new Error("Supported route commands: route add|list|delete");
}

async function policyCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "set") {
    const template = await ctx.api.request<{ id: string }>("POST", "/policies", {
      name: required(stringFlag(ctx.flags, "name"), "name"),
      description: stringFlag(ctx.flags, "description") ?? "",
      rules: parseJsonFlag(ctx.flags, "rules", []),
      isDefault: boolFlag(ctx.flags, "default"),
    });
    const agentId = stringFlag(ctx.flags, "agent-id");
    if (!agentId) return template;
    const assignment = await ctx.api.request(
      "POST",
      `/policies/${encodeURIComponent(template.id)}/assign`,
      {
        agentIds: [agentId],
      },
    );
    return { template, assignment };
  }
  if (action === "list") return ctx.api.request("GET", "/policies");
  throw new Error("Supported policy commands: policy set|list");
}

async function approvalsCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "list") {
    const params = new URLSearchParams();
    if (stringFlag(ctx.flags, "status"))
      params.set("status", stringFlag(ctx.flags, "status") as string);
    if (stringFlag(ctx.flags, "limit"))
      params.set("limit", stringFlag(ctx.flags, "limit") as string);
    return ctx.api.request("GET", `/approvals${params.size ? `?${params}` : ""}`);
  }
  if (action === "stats") return ctx.api.request("GET", "/approvals/stats");
  if (action === "approve") {
    const txId = required(stringFlag(ctx.flags, "tx-id"), "tx-id");
    const result = await ctx.api.request("POST", `/approvals/${encodeURIComponent(txId)}/approve`, {
      comment: stringFlag(ctx.flags, "comment"),
    });
    return {
      result,
      note: "If this is a vault transaction, the API requires execution through POST /vault/:agentId/approve/:txId.",
    };
  }
  if (action === "deny") {
    const txId = required(stringFlag(ctx.flags, "tx-id"), "tx-id");
    return ctx.api.request("POST", `/approvals/${encodeURIComponent(txId)}/deny`, {
      reason: required(stringFlag(ctx.flags, "reason"), "reason"),
    });
  }
  throw new Error("Supported approvals commands: approvals list|stats|approve|deny");
}

async function auditCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "list") {
    const params = new URLSearchParams();
    if (stringFlag(ctx.flags, "limit")) params.set("limit", stringFlag(ctx.flags, "limit")!);
    if (stringFlag(ctx.flags, "before")) params.set("before", stringFlag(ctx.flags, "before")!);
    return ctx.api.request("GET", `/audit/archives${params.size ? `?${params}` : ""}`);
  }
  if (action === "acknowledge") {
    const archiveId = required(stringFlag(ctx.flags, "archive-id"), "archive-id");
    const file = required(stringFlag(ctx.flags, "file"), "file");
    const acknowledgement = JSON.parse(readFileSync(file, "utf8")) as unknown;
    return ctx.api.request(
      "POST",
      `/audit/archives/${encodeURIComponent(archiveId)}/durability-ack`,
      acknowledgement,
    );
  }
  if (action === "restore") {
    const inputDirectory = required(stringFlag(ctx.flags, "in"), "in");
    const archive = JSON.parse(
      readBoundedRegularFile(
        join(inputDirectory, "manifest.json"),
        MAX_ARCHIVE_ENVELOPE_BYTES,
      ).toString("utf8"),
    ) as {
      archiveId: string;
      manifest: { archiveId: string; chunks: Array<{ index: number; file: string }> };
      manifestSha256: string;
      signature: string;
    };
    if (archive.archiveId !== archive.manifest.archiveId) {
      throw new Error("Archive id does not match the signed manifest");
    }
    assertSafeArchiveChunks(archive.manifest.chunks, true);
    assertSafeArchiveManifestTransport(archive.manifest);
    const started = await ctx.api.request("POST", "/audit/archives/restore", {
      manifest: archive.manifest,
      manifestSha256: archive.manifestSha256,
      signature: archive.signature,
    });
    for (const chunk of archive.manifest.chunks) {
      const jsonl = readBoundedRegularFile(
        join(inputDirectory, chunk.file),
        1024 * 1024,
        chunk.byteLength,
      ).toString("utf8");
      await ctx.api.requestRaw(
        "PUT",
        `/audit/archives/${encodeURIComponent(archive.archiveId)}/restore/chunks/${chunk.index}`,
        jsonl,
        "application/x-ndjson; charset=utf-8",
      );
    }
    const completed = await ctx.api.request(
      "POST",
      `/audit/archives/${encodeURIComponent(archive.archiveId)}/restore/complete`,
      {},
    );
    return { started, completed };
  }
  if (action === "export") {
    // Validate the requested trust claim before creating an archive or writing
    // any local files. A malformed verification request must have no effects.
    const verification = auditArchiveVerificationMode(ctx.flags);
    const fromSeq = intFlag(ctx.flags, "from");
    const toSeq = intFlag(ctx.flags, "to");
    if (fromSeq === undefined) throw new Error("--from is required");
    if (toSeq === undefined) throw new Error("--to is required");
    const out = required(stringFlag(ctx.flags, "out"), "out");
    const chunkSize = intFlag(ctx.flags, "chunk-size");
    const archive = await ctx.api.request<{
      archiveId: string;
      manifest: { chunks: ArchiveChunkReference[] };
      manifestSha256: string;
      signature: string;
      publicKey: string;
      status: string;
      sealedAt: string;
      prunedAt: string | null;
    }>("POST", "/audit/archives", { fromSeq, toSeq, chunkSize });
    assertSafeArchiveChunks(archive.manifest.chunks, true);
    assertSafeArchiveManifestTransport(archive.manifest);
    mkdirSync(out, { recursive: true, mode: 0o700 });
    const manifestPath = join(out, "manifest.json");
    if (existsSync(manifestPath)) {
      const existing = JSON.parse(
        readBoundedRegularFile(manifestPath, MAX_ARCHIVE_ENVELOPE_BYTES).toString("utf8"),
      ) as { manifestSha256?: string };
      if (existing.manifestSha256 !== archive.manifestSha256) {
        throw new Error("Existing export manifest belongs to a different archive");
      }
    } else {
      writeFileSync(manifestPath, `${JSON.stringify(archive, null, 2)}\n`, {
        mode: 0o600,
        flag: "wx",
      });
    }
    for (const chunk of archive.manifest.chunks) {
      const path = join(out, chunk.file);
      if (existsSync(path)) {
        const existing = readBoundedRegularFile(path, 1024 * 1024, chunk.byteLength);
        if (createHash("sha256").update(existing).digest("hex") !== chunk.sha256) {
          throw new Error(`Existing chunk ${chunk.file} does not match the signed manifest`);
        }
        continue;
      }
      const jsonl = await ctx.api.requestText(
        `/audit/archives/${encodeURIComponent(archive.archiveId)}/chunks/${chunk.index}`,
      );
      const bytes = new TextEncoder().encode(jsonl);
      if (
        chunk.byteLength === undefined ||
        bytes.length !== chunk.byteLength ||
        chunk.sha256 === undefined ||
        createHash("sha256").update(bytes).digest("hex") !== chunk.sha256
      ) {
        throw new Error(`Downloaded chunk ${chunk.file} does not match the signed manifest`);
      }
      writeFileSync(path, jsonl, { mode: 0o600, flag: "wx" });
    }
    if (verification.mode !== "none") {
      const args = [
        join(import.meta.dir, "../../../scripts/verify-audit-archive.mjs"),
        manifestPath,
        out,
      ];
      if (verification.fingerprint) {
        args.push("--expected-key-fingerprint", verification.fingerprint);
      }
      if (verification.keyId) args.push("--expected-key-id", verification.keyId);
      if (verification.mode === "integrity-only") {
        args.push("--integrity-only");
        console.error(
          "INTEGRITY ONLY: the embedded signing key is not an independent trust anchor; " +
            "this does not authenticate the archive signer.",
        );
      }
      const result = spawnSync(process.execPath, args, { stdio: "inherit" });
      if (result.status !== 0) throw new Error("Offline audit archive verification failed");
    }
    return {
      archiveId: archive.archiveId,
      wrote: out,
      chunks: archive.manifest.chunks.length,
      verification: verification.mode,
    };
  }
  if (action !== "bundle") {
    throw new Error("Supported audit commands: audit bundle|export|list|restore|acknowledge");
  }
  const params = new URLSearchParams();
  params.set("from", String(intFlag(ctx.flags, "from") ?? 1));
  const to = intFlag(ctx.flags, "to");
  if (to !== undefined) params.set("to", String(to));
  const bundle = await ctx.api.request("GET", `/audit/bundle?${params}`);
  const out = stringFlag(ctx.flags, "out");
  if (out) writeOwnerOnlyFile(out, JSON.stringify(bundle, null, 2));
  if (boolFlag(ctx.flags, "verify")) {
    if (!out) throw new Error("--verify requires --out so the offline verifier has a file");
    const result = spawnSync(process.execPath, [evidenceBundleVerifierScript(), out], {
      stdio: "inherit",
    });
    if (result.status !== 0) throw new Error("Offline audit bundle verification failed");
  }
  return out ? { wrote: out, verified: boolFlag(ctx.flags, "verify"), bundle } : bundle;
}

/**
 * Provider-action command group: thin convenience wrappers over the
 * governed-provider routes. These are convenience only; the authoritative proof is
 * `scripts/provider-authority-golden-path.mjs`. No new route or authority is
 * introduced; each subcommand maps 1:1 to an existing route. Consequential
 * writes are gated by the SAME approval/execute lifecycle regardless of caller.
 */
async function providerActionCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "create") {
    // Create a provider action. The route's strict top-level schema accepts
    // exactly {workspaceId, providerAccountId, operationKey, arguments,
    // idempotencyKey}; the API canonicalizes + digests the arguments and hashes
    // the idempotency key server-side. `--arguments` is the adapter argument JSON
    // (e.g. {owner, repo, pullNumber, body}), NOT a pre-built canonical action.
    return ctx.api.request("POST", "/v2/provider-actions", {
      workspaceId: required(stringFlag(ctx.flags, "workspace-id"), "workspace-id"),
      providerAccountId: required(stringFlag(ctx.flags, "account-id"), "account-id"),
      operationKey: required(stringFlag(ctx.flags, "operation"), "operation"),
      arguments: parseJsonFlag(ctx.flags, "arguments", undefined),
      idempotencyKey: required(stringFlag(ctx.flags, "idempotency-key"), "idempotency-key"),
    });
  }
  const id = () => encodeURIComponent(required(stringFlag(ctx.flags, "id"), "id"));
  if (action === "get") {
    return ctx.api.request("GET", `/v2/provider-actions/${id()}`);
  }
  if (action === "approval") {
    // Approval detail requires a human session and recent MFA.
    return ctx.api.request("GET", `/v2/provider-actions/${id()}/approval`);
  }
  if (action === "approve" || action === "deny") {
    // A typed reason is required for both decisions.
    // The route ALSO requires an idempotencyKey (rejects with
    // APPROVAL_FIELD_INVALID otherwise) so a retried decision cannot double-apply.
    const reason = required(stringFlag(ctx.flags, "reason"), "reason");
    const actionId = required(stringFlag(ctx.flags, "id"), "id");
    const idempotencyKey =
      stringFlag(ctx.flags, "idempotency-key") ?? `decide-${action}-${actionId}`.slice(0, 255);
    // Build the decide body with OPTIONAL fields OMITTED (not null): the route's
    // strict schema rejects a `reasonCode: null` via isApprovalReasonCode(null)
    // (only a valid code string, or an ABSENT key, is accepted). Sending null
    // when --reason-code is unset would fail APPROVAL_FIELD_INVALID for the
    // common approve/deny case.
    const decideBody: Record<string, unknown> = {
      decision: action === "approve" ? "approve" : "deny",
      reason,
      expectedVersion: intFlag(ctx.flags, "expected-version"),
      expectedRequestHash: stringFlag(ctx.flags, "expected-request-hash"),
      expectedActionDigest: stringFlag(ctx.flags, "expected-action-digest"),
      idempotencyKey,
    };
    const reasonCode = stringFlag(ctx.flags, "reason-code");
    if (reasonCode !== undefined) decideBody.reasonCode = reasonCode;
    return ctx.api.request("POST", `/v2/provider-actions/${id()}/approval`, decideBody);
  }
  if (action === "execute") {
    // Typed system resume. The body carries only idempotencyKey; actor/action
    // substitution is rejected server-side (RESUME_ACTOR_SUBSTITUTION_FORBIDDEN).
    const idempotencyKey = stringFlag(ctx.flags, "idempotency-key");
    return ctx.api.request(
      "POST",
      `/v2/provider-actions/${id()}/execute`,
      idempotencyKey ? { idempotencyKey } : undefined,
    );
  }
  if (action === "case") {
    // The case manifest requires owner or admin authorization and recent MFA.
    return ctx.api.request("GET", `/v2/provider-actions/${id()}/case`);
  }
  if (action === "evidence") {
    // The signed evidence bundle can be written and verified offline with a
    // trusted key fingerprint (E7): --out bundle.json [--verify --fp <hex>].
    const bundle = await ctx.api.request("GET", `/v2/provider-actions/${id()}/evidence`);
    const out = stringFlag(ctx.flags, "out");
    if (out) writeOwnerOnlyFile(out, JSON.stringify(bundle, null, 2));
    if (boolFlag(ctx.flags, "verify")) {
      if (!out) throw new Error("--verify requires --out so the offline verifier has a file");
      const fp = stringFlag(ctx.flags, "fp") ?? stringFlag(ctx.flags, "expected-key-fingerprint");
      const args = [evidenceBundleVerifierScript(), out];
      // E7 / M09: bind trust to an out-of-band fingerprint. Warn loudly if absent
      // (verifying against the embedded key proves self-consistency ONLY).
      if (fp) args.push("--expected-key-fingerprint", fp);
      else
        console.error(
          "WARNING: no --fp supplied; verifying against the EMBEDDED key proves " +
            "self-consistency only, NOT trust to a known signing root.",
        );
      const result = spawnSync(process.execPath, args, { stdio: "inherit" });
      if (result.status !== 0) throw new Error("Offline evidence bundle verification failed");
    }
    return out ? { wrote: out, verified: boolFlag(ctx.flags, "verify"), bundle } : bundle;
  }
  throw new Error(
    "Supported provider-action commands: create|get|approval|approve|deny|execute|case|evidence",
  );
}

async function main(argv: string[]) {
  const parsed = parseArgs(argv);
  const [command, action] = parsed.positional;
  const ctx = createContext(parsed.flags);

  if (!command || command === "help" || boolFlag(parsed.flags, "help")) {
    console.log(HELP);
    return;
  }
  if (command === "init") {
    printResult(
      runInit({
        envPath: stringFlag(parsed.flags, "env"),
        force: boolFlag(parsed.flags, "force"),
        runMigrations: boolFlag(parsed.flags, "migrate"),
        databaseUrl: stringFlag(parsed.flags, "database-url"),
        apiUrl: stringFlag(parsed.flags, "api-url"),
      }),
      ctx.format,
    );
    return;
  }
  if (command === "doctor") {
    const strict = boolFlag(parsed.flags, "strict");
    const result = await runDoctor({
      strict,
      envPath: stringFlag(parsed.flags, "env"),
      api: ctx.api,
    });
    printResult(result, ctx.format);
    if (strict && !result.ok) process.exitCode = 1;
    return;
  }

  const handlers: Record<
    string,
    (action: string | undefined, ctx: CommandContext) => Promise<unknown>
  > = {
    tenant: tenantCommand,
    agent: agentCommand,
    secret: secretCommand,
    route: routeCommand,
    policy: policyCommand,
    approvals: approvalsCommand,
    audit: auditCommand,
    "provider-action": providerActionCommand,
  };
  const handler = handlers[command];
  if (!handler) throw new Error(`Unknown command '${command}'. Run steward help.`);
  printResult(
    await handler(action, ctx),
    ctx.format,
    command === "agent" && action === "token" && boolFlag(parsed.flags, "show-token"),
  );
}

if (import.meta.main) {
  const cliArgv = Bun.argv.slice(2);
  main(cliArgv).catch((error) => {
    const parsed = parseArgs(cliArgv);
    const sensitiveFlagNames = ["token", "tenant-key", "platform-key", "api-key", "value"];
    const knownSecrets = [
      ...sensitiveFlagNames.map((name) => stringFlag(parsed.flags, name)),
      process.env.STEWARD_TOKEN,
      process.env.STEWARD_API_TOKEN,
      process.env.STEWARD_TENANT_KEY,
      process.env.STEWARD_PLATFORM_KEY,
    ];
    const message = redactSensitiveText(
      error instanceof Error ? error.message : String(error),
      knownSecrets,
    );
    console.error(`steward: ${sanitizeTerminalText(message)}`);
    process.exit(1);
  });
}
