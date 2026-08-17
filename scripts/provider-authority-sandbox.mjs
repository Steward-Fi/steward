#!/usr/bin/env node
/** Gate D operator harness. It never persists or prints a provider credential. */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildDispatchEnvironment,
  isLiveRateLimitObservation,
  mintInstallationCredential,
  reconcileGithubMarker,
  requestJson,
  revokeInstallationToken,
  scrub,
  validateBuildPrerequisites,
  validateEnvironment,
  verifyInstallationScope,
} from "./lib/provider-authority-sandbox-lib.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, "artifacts", "provider-authority", "sandbox");
const CLAIM =
  "Live behavior is recorded exactly as observed. Hermetic classification is not a live " +
  "rate-limit observation; Gate D remains STOP unless every required live observation passes.";
const MAX_CHILD_OUTPUT_BYTES = 1024 * 1024;
const ARTIFACT_NAMES = [
  "test-report.json",
  "image-commit.txt",
  "dispatch-count.json",
  "verifier-report.txt",
  "canary-report.json",
  "provider-reconciliation.json",
  "manifest.json",
];

function fail(message) {
  console.error(`[sandbox] FAIL (fail-closed): ${message}`);
  process.exitCode = 1;
}

async function stewardRaw(env, path, token, options = {}) {
  const base = env.STEWARD_API_URL.replace(/\/$/, "");
  return requestJson(
    `${base}${path}`,
    {
      ...options,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "x-steward-tenant": env.STEWARD_TENANT_ID,
        ...(options.headers ?? {}),
      },
    },
    fetch,
    { expectedOrigin: base },
  );
}

async function steward(env, path, token, options = {}) {
  const { response, body } = await stewardRaw(env, path, token, options);
  if (!response.ok) {
    throw new Error(`Steward ${options.method ?? "GET"} ${path} failed (${response.status})`);
  }
  return body;
}

export async function prepareApprovedWrite(env, marker, body, stewardImpl = steward) {
  const created = await stewardImpl(env, "/v2/provider-actions", env.STEWARD_AGENT_JWT, {
    method: "POST",
    body: JSON.stringify({
      workspaceId: env.STEWARD_SANDBOX_WORKSPACE_ID,
      providerAccountId: env.STEWARD_SANDBOX_PROVIDER_ACCOUNT_ID,
      operationKey: "github.pr.comment.create",
      arguments: {
        owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
        repo: env.STEWARD_SANDBOX_GITHUB_REPO,
        pullNumber: Number(env.STEWARD_SANDBOX_GITHUB_PR_NUMBER),
        body,
      },
      idempotencyKey: `gate-d-${marker}`,
    }),
  });
  if (!created.id || created.status !== "pending_approval") {
    throw new Error("provider action did not require approval");
  }
  const approvalResponse = await stewardImpl(
    env,
    `/v2/provider-actions/${encodeURIComponent(created.id)}/approval`,
    env.STEWARD_APPROVER_JWT,
  );
  const approval = approvalResponse.data ?? approvalResponse;
  await stewardImpl(
    env,
    `/v2/provider-actions/${encodeURIComponent(created.id)}/approval`,
    env.STEWARD_APPROVER_JWT,
    {
      method: "POST",
      body: JSON.stringify({
        decision: "approve",
        expectedVersion: approval.version,
        expectedRequestHash: created.requestHash,
        expectedActionDigest: created.actionDigest,
        reason: "throwaway Gate D sandbox",
        idempotencyKey: `approve-${marker}`,
      }),
    },
  );
  const executeResponse = await stewardImpl(
    env,
    `/v2/provider-actions/${encodeURIComponent(created.id)}/execute`,
    env.STEWARD_AGENT_JWT,
    { method: "POST" },
  );
  const execution = executeResponse.data ?? executeResponse;
  if (execution.status !== "execution_ready") {
    throw new Error(`execute did not reach execution_ready (got ${execution.status ?? "unknown"})`);
  }
  return created;
}

export function requireRawCaseManifest(caseRecord, intentId) {
  if (!caseRecord || caseRecord.caseId !== intentId) {
    throw new Error("live case response did not contain the expected case manifest");
  }
  return caseRecord;
}

export function runDispatchChild(
  env,
  intentId,
  { pauseAfterUpstream = false, timeoutMs = 5_000, spawnImpl = spawn } = {},
) {
  return new Promise((resolve) => {
    const child = spawnImpl(
      "bun",
      [join(ROOT, "scripts/provider-authority-dispatch-child.ts"), intentId, env.STEWARD_TENANT_ID],
      {
        cwd: ROOT,
        env: buildDispatchEnvironment(env, pauseAfterUpstream),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    let reachedAfterUpstream = false;
    let outputExceeded = false;
    let spawnError = false;
    let killTimer;
    child.stdout.on("data", (chunk) => {
      if (Buffer.byteLength(stdout) + chunk.byteLength > MAX_CHILD_OUTPUT_BYTES) {
        outputExceeded = true;
        child.kill("SIGKILL");
        return;
      }
      stdout += chunk;
      if (pauseAfterUpstream && stdout.includes('"phase":"after_upstream"')) {
        reachedAfterUpstream = true;
        if (!killTimer) killTimer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
      }
    });
    child.stderr.on("data", (chunk) => {
      if (Buffer.byteLength(stderr) + chunk.byteLength > MAX_CHILD_OUTPUT_BYTES) {
        outputExceeded = true;
        child.kill("SIGKILL");
        return;
      }
      stderr += chunk;
    });
    child.on("error", () => {
      // Node follows this with `close`; retain only a boolean so an OS error
      // cannot echo a sensitive environment value into artifacts or logs.
      spawnError = true;
    });
    const safetyTimer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("close", (code, signal) => {
      if (killTimer) clearTimeout(killTimer);
      clearTimeout(safetyTimer);
      let result = null;
      try {
        const finalLine = stdout.trim().split("\n").at(-1);
        result = finalLine ? JSON.parse(finalLine) : null;
      } catch {
        // A malformed child result is retained only as a non-secret failure.
      }
      resolve({
        code,
        signal,
        result,
        stdout,
        stderr,
        reachedAfterUpstream,
        timedOut: signal === "SIGKILL" && reachedAfterUpstream,
        outputExceeded,
        spawnError,
      });
    });
  });
}

function writeArtifact(name, value, secretValues) {
  writeFileSync(join(OUT_DIR, name), `${scrub(value, secretValues)}\n`, { mode: 0o600 });
}

async function main() {
  const env = process.env;
  try {
    validateEnvironment(env);
    validateBuildPrerequisites(ROOT);
  } catch (error) {
    return fail(error.message);
  }
  if (process.argv.includes("--preflight")) {
    console.log(
      "[sandbox] preflight OK — required variables validated; zero network requests made",
    );
    return;
  }

  mkdirSync(OUT_DIR, { recursive: true });
  // A failed rerun must not inherit a manifest or supporting file from an older
  // run. The manifest is written last, so its presence means this invocation
  // completed the entire artifact pipeline.
  for (const name of [...ARTIFACT_NAMES, ".evidence-for-verifier.json", ".tampered-evidence.json"])
    rmSync(join(OUT_DIR, name), { force: true });
  let githubToken;
  const activeGithubTokens = new Set();
  const marker = `steward-gate-d:${crypto.randomUUID()}`;
  const report = {
    schemaVersion: 2,
    startedAt: new Date().toISOString(),
    steps: [],
    gateD: "STOP",
  };
  const secretValues = [
    env.GITHUB_APP_PRIVATE_KEY,
    env.STEWARD_AGENT_JWT,
    env.STEWARD_APPROVER_JWT,
    env.STEWARD_MASTER_PASSWORD,
    env.STEWARD_EXECUTION_AUTH_SECRET,
    env.STEWARD_AUDIT_HMAC_KEY,
    env.STEWARD_AUDIT_SIGNING_KEY,
  ].filter((value) => typeof value === "string");

  try {
    const installation = await mintInstallationCredential(env);
    githubToken = installation.token;
    activeGithubTokens.add(githubToken);
    secretValues.push(githubToken);
    await verifyInstallationScope(installation, {
      owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
      repo: env.STEWARD_SANDBOX_GITHUB_REPO,
    });
    report.steps.push({
      id: "setup-token",
      status: "pass",
      detail: "short-lived token minted; exact permissions and one-repo scope verified",
    });

    await steward(
      env,
      `/secrets/${encodeURIComponent(env.STEWARD_SANDBOX_SECRET_ID)}/rotate`,
      env.STEWARD_APPROVER_JWT,
      { method: "POST", body: JSON.stringify({ value: githubToken }) },
    );
    githubToken = undefined;
    report.steps.push({
      id: "setup-secret",
      status: "pass",
      detail: "credential rotated through recent-MFA secret API",
    });

    const read = await steward(env, "/v2/provider-actions", env.STEWARD_AGENT_JWT, {
      method: "POST",
      body: JSON.stringify({
        workspaceId: env.STEWARD_SANDBOX_WORKSPACE_ID,
        providerAccountId: env.STEWARD_SANDBOX_PROVIDER_ACCOUNT_ID,
        operationKey: "github.issue.list",
        arguments: {
          owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
          repo: env.STEWARD_SANDBOX_GITHUB_REPO,
        },
        idempotencyKey: `gate-d-read-${marker}`,
      }),
    });
    if (read.status !== "stub_succeeded") {
      throw new Error("M02 read authority path was not allowed");
    }
    report.steps.push({ id: "M02", status: "pass", detail: "read authority path allowed" });

    const crossScope = await stewardRaw(env, "/v2/provider-actions", env.STEWARD_AGENT_JWT, {
      method: "POST",
      body: JSON.stringify({
        workspaceId: crypto.randomUUID(),
        providerAccountId: env.STEWARD_SANDBOX_PROVIDER_ACCOUNT_ID,
        operationKey: "github.issue.list",
        arguments: {
          owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
          repo: env.STEWARD_SANDBOX_GITHUB_REPO,
        },
        idempotencyKey: `gate-d-cross-${marker}`,
      }),
    });
    if (crossScope.response.status !== 404) {
      throw new Error(
        `M03 cross-scope probe did not fail non-enumerating (got ${crossScope.response.status})`,
      );
    }
    report.steps.push({ id: "M03", status: "pass", detail: "cross-scope probe returned 404" });

    // Mint against secret version N, then rotate the same in-memory credential
    // to version N+1. The old authorization must fail before decrypt/forward.
    const staleMarker = `${marker}:stale-secret`;
    const staleCreated = await prepareApprovedWrite(
      env,
      staleMarker,
      `Steward Gate D stale probe (must not post): ${staleMarker}`,
    );
    await steward(
      env,
      `/secrets/${encodeURIComponent(env.STEWARD_SANDBOX_SECRET_ID)}/rotate`,
      env.STEWARD_APPROVER_JWT,
      { method: "POST", body: JSON.stringify({ value: installation.token }) },
    );
    const staleDispatch = await runDispatchChild(env, staleCreated.id);
    if (staleDispatch.result?.code !== "EXEC_AUTH_STALE_SECRET") {
      throw new Error(
        `M05 stale-secret probe did not fail before forward (got ${staleDispatch.result?.code ?? "no result"})`,
      );
    }
    report.steps.push({
      id: "M05",
      status: "pass",
      detail: "live post-mint secret rotation denied dispatch before provider I/O",
    });

    const created = await prepareApprovedWrite(
      env,
      marker,
      `Steward Gate D sandbox marker: ${marker}`,
    );
    const intentId = created.id;
    report.steps.push({ id: "M04", status: "pass", detail: "write required approval" });
    report.steps.push({ id: "M06", status: "pass", detail: "recent-MFA approval accepted" });
    report.steps.push({
      id: "M09",
      status: "pass",
      detail: "execute reached execution_ready",
      intentId,
    });

    // This worker reaches the real default forwarder, receives the upstream
    // response, then pauses. Killing only that child models the exact crash
    // window without weakening the server or adding a forgeable dispatch route.
    const childTimeoutMs = Number(env.STEWARD_SANDBOX_CHILD_TIMEOUT_MS ?? 2_000);
    if (!Number.isSafeInteger(childTimeoutMs) || childTimeoutMs < 100 || childTimeoutMs >= 30_000) {
      throw new Error("STEWARD_SANDBOX_CHILD_TIMEOUT_MS must be an integer from 100 through 29999");
    }
    const racers = await Promise.all(
      Array.from({ length: 8 }, () =>
        runDispatchChild(env, intentId, { pauseAfterUpstream: true, timeoutMs: childTimeoutMs }),
      ),
    );
    const winners = racers.filter((result) => result.timedOut && result.reachedAfterUpstream);
    const losers = racers.filter((result) => !result.timedOut);
    if (
      racers.some((result) => result.spawnError || result.outputExceeded) ||
      winners.length !== 1 ||
      losers.length !== 7 ||
      losers.some(
        (result) => !["EXEC_AUTH_CLAIM_LOST", "EXEC_TERMINAL_STATE"].includes(result.result?.code),
      )
    ) {
      throw new Error("M07 concurrent workers did not produce exactly one upstream winner");
    }
    const replay = await runDispatchChild(env, intentId);
    if (replay.spawnError) throw new Error("replay child failed to spawn");
    if (replay.outputExceeded) throw new Error("replay child exceeded the output limit");
    const childOutput = [...racers, replay]
      .map((result) => `${result.stdout}\n${result.stderr}`)
      .join("\n");
    if (secretValues.some((value) => value.length >= 4 && childOutput.includes(value))) {
      throw new Error("credential canary appeared in dispatch child output");
    }
    if (replay.timedOut || replay.result?.code !== "EXEC_TERMINAL_STATE") {
      throw new Error("fresh-worker replay was not rejected as terminal");
    }
    report.steps.push({
      id: "M07",
      status: "pass",
      detail: "eight live workers raced; exactly one crossed the upstream barrier",
    });
    report.steps.push({
      id: "M08/M14",
      status: "pass",
      detail: "isolated post-upstream crash window; fresh-worker replay rejected",
      replay: replay.result,
    });

    // Mint a separate, fresh read token only in memory. Reconciliation is
    // bounded provider GET; Steward has no reconciliation service to overclaim.
    const reconciliationInstallation = await mintInstallationCredential(env);
    githubToken = reconciliationInstallation.token;
    activeGithubTokens.add(githubToken);
    secretValues.push(githubToken);
    await verifyInstallationScope(reconciliationInstallation, {
      owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
      repo: env.STEWARD_SANDBOX_GITHUB_REPO,
    });
    const reconciliation = await reconcileGithubMarker({
      apiBase: env.GITHUB_API_URL,
      owner: env.STEWARD_SANDBOX_GITHUB_OWNER,
      repo: env.STEWARD_SANDBOX_GITHUB_REPO,
      pullNumber: env.STEWARD_SANDBOX_GITHUB_PR_NUMBER,
      marker,
      token: githubToken,
    });
    writeArtifact("provider-reconciliation.json", reconciliation, secretValues);
    report.steps.push({
      id: "M17",
      status: reconciliation.outcome === "found" ? "pass" : "stop",
      outcome: reconciliation.outcome,
    });

    for (const token of [...activeGithubTokens]) {
      await revokeInstallationToken(token);
      activeGithubTokens.delete(token);
    }
    githubToken = undefined;
    report.steps.push({
      id: "setup-token-revocation",
      status: "pass",
      detail: "all minted installation tokens revoked; vaulted dispatch token is inert",
    });

    const caseRecord = await steward(
      env,
      `/v2/provider-actions/${encodeURIComponent(intentId)}/case`,
      env.STEWARD_APPROVER_JWT,
    );
    // The live `/case` route returns ProviderCaseManifestV1 directly (unlike
    // approval detail, which uses an `{ ok, data }` envelope).
    const caseManifest = requireRawCaseManifest(caseRecord, intentId);
    const evidence = await steward(
      env,
      `/v2/provider-actions/${encodeURIComponent(intentId)}/evidence`,
      env.STEWARD_APPROVER_JWT,
    );
    const sensitiveEvidenceSurface = JSON.stringify({ caseRecord, evidence });
    if (
      secretValues.some((value) => value.length >= 4 && sensitiveEvidenceSurface.includes(value)) ||
      /Bearer\s+[A-Za-z0-9._~-]+|(?:gh[psuor]_|github_pat_)[A-Za-z0-9_]+|-----BEGIN [^-]+-----/i.test(
        sensitiveEvidenceSurface,
      )
    ) {
      throw new Error("M15 credential material appeared in the live case/evidence response");
    }
    report.steps.push({
      id: "M15",
      status: "pass",
      detail: "live case and evidence responses contained no credential material",
    });
    // Evidence is a mode-0600 verifier input only and is deleted after both
    // checks. The stable artifact set records the verifier result, not a second
    // potentially sensitive copy of the bundle.
    const evidencePath = join(OUT_DIR, ".evidence-for-verifier.json");
    writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
    const clean = Bun.spawnSync(
      [
        "node",
        join(ROOT, "scripts/verify-evidence-bundle.mjs"),
        evidencePath,
        "--expected-key-fingerprint",
        env.STEWARD_AUDIT_SIGNING_KEY_FINGERPRINT,
      ],
      { cwd: ROOT },
    );
    const tampered = JSON.parse(readFileSync(evidencePath, "utf8"));
    if (!tampered.bundle?.events?.[0]) throw new Error("evidence has no event to tamper");
    tampered.bundle.events[0].action = `${tampered.bundle.events[0].action}.tampered`;
    const tamperedPath = join(OUT_DIR, ".tampered-evidence.json");
    writeFileSync(tamperedPath, JSON.stringify(tampered), { mode: 0o600 });
    const dirty = Bun.spawnSync(
      [
        "node",
        join(ROOT, "scripts/verify-evidence-bundle.mjs"),
        tamperedPath,
        "--expected-key-fingerprint",
        env.STEWARD_AUDIT_SIGNING_KEY_FINGERPRINT,
      ],
      { cwd: ROOT },
    );
    unlinkSync(tamperedPath);
    unlinkSync(evidencePath);
    const verifierOk = clean.exitCode === 0 && dirty.exitCode === 1;
    const honestIncompleteCase =
      ["incomplete", "unknown"].includes(caseManifest.completeness) &&
      ["executing", "outcome_unknown"].includes(caseManifest.terminalState) &&
      Array.isArray(caseManifest.incompletenessReasons) &&
      caseManifest.incompletenessReasons.length > 0;
    report.steps.push({
      id: "M18",
      status: verifierOk && honestIncompleteCase ? "pass" : "stop",
      caseVersion: caseManifest.schemaVersion ?? null,
      completeness: caseManifest.completeness ?? null,
      terminalState: caseManifest.terminalState ?? null,
    });

    // GitHub may not emit a real rate limit during this run. Never induce abuse
    // or turn the hermetic classifier proof into a fabricated live observation.
    const liveRateLimitObserved = reconciliation.observations.some(isLiveRateLimitObservation);
    report.steps.push({
      id: "M16",
      status: liveRateLimitObserved ? "pass" : "not_observed",
      detail: liveRateLimitObserved
        ? "bounded provider rate-limit response observed and classified"
        : "403/429 classifier is hermetically tested; no live response was manufactured",
    });
    report.gateD =
      reconciliation.outcome === "found" &&
      verifierOk &&
      honestIncompleteCase &&
      liveRateLimitObserved
        ? "GO"
        : "STOP";
    const git = Bun.spawnSync(["git", "rev-parse", "HEAD"], { cwd: ROOT });
    const sha = git.exitCode === 0 ? git.stdout.toString().trim() : "unknown";
    writeArtifact("image-commit.txt", sha, secretValues);
    writeArtifact(
      "dispatch-count.json",
      {
        concurrentWorkers: racers.length,
        upstreamWinners: winners.length,
        winner: "killed_after_upstream",
        replay: replay.result,
        expectedProviderPosts: 1,
      },
      secretValues,
    );
    writeArtifact(
      "verifier-report.txt",
      `clean=${clean.exitCode === 0 ? "PASS" : "FAIL"}\ntampered=${dirty.exitCode === 1 ? "FAIL_AS_REQUIRED" : "UNEXPECTED"}`,
      secretValues,
    );
    writeArtifact("test-report.json", report, secretValues);
    const artifactText = [
      "test-report.json",
      "image-commit.txt",
      "dispatch-count.json",
      "verifier-report.txt",
      "provider-reconciliation.json",
    ]
      .map((name) => readFileSync(join(OUT_DIR, name), "utf8"))
      .join("\n");
    if (secretValues.some((value) => value.length >= 4 && artifactText.includes(value))) {
      throw new Error("credential canary appeared in persisted artifacts");
    }
    writeArtifact(
      "canary-report.json",
      { clean: true, note: "all persisted artifacts passed the literal credential sweep" },
      secretValues,
    );
    const canaryText = readFileSync(join(OUT_DIR, "canary-report.json"), "utf8");
    if (secretValues.some((value) => value.length >= 4 && canaryText.includes(value))) {
      throw new Error("credential canary appeared in canary report");
    }
    // The manifest is the completion marker and is deliberately written last.
    writeArtifact(
      "manifest.json",
      {
        schemaVersion: 2,
        claimWording: CLAIM,
        gateD: report.gateD,
        marker,
        artifacts: [
          "test-report.json",
          "image-commit.txt",
          "dispatch-count.json",
          "verifier-report.txt",
          "canary-report.json",
          "provider-reconciliation.json",
        ],
      },
      secretValues,
    );
    console.log(
      `[sandbox] completed honest live observation; Gate D ${report.gateD}; artifacts: ${OUT_DIR}`,
    );
    if (report.gateD !== "GO") process.exitCode = 2;
  } catch (error) {
    writeArtifact(
      "test-report.json",
      { ...report, error: error.message, gateD: "STOP" },
      secretValues,
    );
    fail(error.message);
  } finally {
    githubToken = undefined;
    // Best-effort cleanup on every failure path. A cleanup failure is reported
    // without printing the token; GitHub's normal one-hour expiry remains the
    // final backstop if the provider is unreachable.
    for (const token of [...activeGithubTokens]) {
      try {
        await revokeInstallationToken(token);
        activeGithubTokens.delete(token);
      } catch (error) {
        console.error(`[sandbox] token cleanup warning: ${error.message}`);
        process.exitCode = 1;
      }
    }
    for (const name of [".evidence-for-verifier.json", ".tampered-evidence.json"]) {
      const path = join(OUT_DIR, name);
      if (existsSync(path)) unlinkSync(path);
    }
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) main();
