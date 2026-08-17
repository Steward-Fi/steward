import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ApiError, StewardApiClient } from "./api";
import { describeSecret } from "./format";

export type DoctorCheck = {
  name: string;
  ok: boolean;
  detail: string;
};

export type DoctorOptions = {
  strict?: boolean;
  envPath?: string;
  api?: StewardApiClient;
};

type ReadyCheck = { ok?: unknown; required?: unknown; error?: unknown; detail?: unknown };
type ReadyResponse = {
  checks?: Record<string, ReadyCheck>;
};

function readyResponseFromError(error: unknown): ReadyResponse | null {
  if (!(error instanceof ApiError) || !error.body || typeof error.body !== "object") return null;
  const body = error.body as { checks?: unknown; data?: unknown };
  const candidate =
    body.checks !== undefined
      ? body
      : body.data && typeof body.data === "object"
        ? (body.data as { checks?: unknown })
        : null;
  return candidate && candidate.checks && typeof candidate.checks === "object"
    ? (candidate as ReadyResponse)
    : null;
}

function operationalDetail(check: ReadyCheck | undefined, fallback: string): string {
  if (!check) return fallback;
  if (typeof check.error === "string") return check.error;
  return check.detail === undefined
    ? check.ok === true
      ? "ok"
      : fallback
    : JSON.stringify(check.detail);
}

function parseEnv(path: string): Record<string, string> {
  if (!existsSync(path)) return {};
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    out[trimmed.slice(0, idx)] = trimmed.slice(idx + 1).replace(/^'|'$/g, "");
  }
  return out;
}

export async function runDoctor(
  options: DoctorOptions = {},
): Promise<{ ok: boolean; checks: DoctorCheck[] }> {
  const env = { ...parseEnv(resolve(options.envPath ?? ".env")), ...process.env };
  const checks: DoctorCheck[] = [];
  const required = [
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_JWT_SECRET",
    "STEWARD_EMAIL_CODE_SECRET",
    "STEWARD_EXECUTION_AUTH_SECRET",
    "STEWARD_KDF_SALT",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_AUDIT_SIGNING_KEY",
  ];
  for (const key of required) {
    // detail reports ONLY presence + byte length — never any substring of the
    // secret value (see describeSecret).
    checks.push({ name: `env:${key}`, ok: Boolean(env[key]), detail: describeSecret(env[key]) });
  }
  checks.push({
    name: "audit:ed25519-key-format",
    ok:
      /^[0-9a-fA-F]{64}$/.test(env.STEWARD_AUDIT_SIGNING_KEY ?? "") ||
      (env.STEWARD_AUDIT_SIGNING_KEY ?? "").includes("BEGIN PRIVATE KEY"),
    detail: "expects PKCS#8 PEM or raw 32-byte hex seed",
  });
  if (options.strict) {
    checks.push({
      name: "strict:platform-scopes",
      ok: Boolean(env.STEWARD_PLATFORM_KEY_SCOPES?.includes("platform:tenant:create")),
      detail: "platform key should include platform:tenant:create for steward tenant create",
    });
    checks.push({
      name: "strict:proxy-request-signing",
      ok: Boolean(env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS),
      detail: "required for production proxy request signing",
    });
    // PR6 governed-route prerequisites (§8.2). A governed provider dispatch needs
    // the PR4 execution-auth secret (mint/claim) AND the PR5 audit signing key
    // (evidence export). Both are already in the `required` list above; this
    // strict check states them as an explicit governed-route readiness gate so a
    // failed run is obvious, not a silent skip (U10). We VERIFY presence here;
    // we do NOT duplicate the secret-format checks.
    checks.push({
      name: "strict:governed-route-prerequisites",
      ok: Boolean(env.STEWARD_EXECUTION_AUTH_SECRET) && Boolean(env.STEWARD_AUDIT_SIGNING_KEY),
      detail:
        "governed provider dispatch requires STEWARD_EXECUTION_AUTH_SECRET (PR4 " +
        "mint/claim) and STEWARD_AUDIT_SIGNING_KEY (PR5 /evidence). Missing either " +
        "fails closed at dispatch/evidence, never a silent pass.",
    });
  }

  const api = options.api ?? new StewardApiClient({ baseUrl: env.STEWARD_API_URL });
  try {
    const health = await api.request("GET", "/health", undefined, { tenant: false });
    checks.push({ name: "api:/health", ok: true, detail: JSON.stringify(health) });
  } catch (error) {
    checks.push({ name: "api:/health", ok: !options.strict, detail: (error as Error).message });
  }
  let readyResponse: ReadyResponse | null = null;
  let readyError: unknown;
  try {
    const requestedAt = Date.now();
    const ready = await api.request<ReadyResponse>("GET", "/ready", undefined, { tenant: false });
    const receivedAt = Date.now();
    readyResponse = ready;
    const readyChecks = ready.checks ?? {};
    checks.push({ name: "api:/ready", ok: true, detail: JSON.stringify(ready) });
    appendReadyChecks(checks, readyChecks, options.strict === true, requestedAt, receivedAt);
  } catch (error) {
    readyError = error;
    readyResponse = readyResponseFromError(error);
    if (readyResponse) {
      const now = Date.now();
      checks.push({
        name: "api:/ready",
        ok: !options.strict,
        detail: JSON.stringify(readyResponse),
      });
      appendReadyChecks(checks, readyResponse.checks ?? {}, options.strict === true, now, now);
    }
  }
  if (!readyResponse) {
    const error = readyError;
    checks.push({
      name: "api:/ready",
      ok: !options.strict,
      detail: error instanceof Error ? error.message : "readiness response unavailable",
    });
    for (const name of [
      "ops:migration-tip",
      "ops:redis-reachability",
      "ops:proxy-clock-skew",
      "ops:api-database-clock-skew",
    ]) {
      checks.push({ name, ok: !options.strict, detail: "unavailable because /ready failed" });
    }
  }

  try {
    const integrity = await api.request<{
      valid?: unknown;
      chainValid?: unknown;
      checkpointPresent?: unknown;
      checkpointValid?: unknown;
      checkpointAtHead?: unknown;
      checkpointSeq?: unknown;
      chainHeadSeq?: unknown;
      governedRoutes?: ReadyCheck;
    }>("GET", "/audit/integrity");
    checks.push({
      name: "ops:governed-route-inventory",
      ok:
        integrity.governedRoutes?.ok === true ||
        (!options.strict && integrity.governedRoutes?.ok !== false),
      detail: operationalDetail(integrity.governedRoutes, "diagnostic unavailable"),
    });
    checks.push({
      name: "ops:audit-checkpoint-integrity",
      ok: integrity.valid === true || !options.strict,
      detail: JSON.stringify({
        chainValid: integrity.chainValid === true,
        checkpointPresent: integrity.checkpointPresent === true,
        checkpointValid: integrity.checkpointValid === true,
        checkpointAtHead: integrity.checkpointAtHead === true,
        checkpointSeq: integrity.checkpointSeq ?? null,
        chainHeadSeq: integrity.chainHeadSeq ?? null,
      }),
    });
  } catch (error) {
    checks.push({
      name: "ops:governed-route-inventory",
      ok: !options.strict,
      detail: (error as Error).message,
    });
    checks.push({
      name: "ops:audit-checkpoint-integrity",
      ok: !options.strict,
      detail: (error as Error).message,
    });
  }

  return { ok: checks.every((check) => check.ok), checks };
}

function appendReadyChecks(
  checks: DoctorCheck[],
  readyChecks: Record<string, ReadyCheck>,
  strict: boolean,
  requestedAt: number,
  receivedAt: number,
): void {
  for (const [name, source] of [
    ["ops:migration-tip", readyChecks.migrations],
    ["ops:redis-reachability", readyChecks.redis],
    ["ops:proxy-clock-skew", readyChecks.proxyClock],
  ] as const) {
    checks.push({
      name,
      ok: source?.ok === true || source?.required === false || (!strict && source?.ok !== false),
      detail: operationalDetail(source, "diagnostic unavailable"),
    });
  }
  const databaseDetail = readyChecks.database?.detail as
    | { clockSkewMs?: unknown; serverTime?: unknown }
    | undefined;
  const apiTime = Date.parse(String(databaseDetail?.serverTime ?? ""));
  const midpoint = requestedAt + (receivedAt - requestedAt) / 2;
  const apiSkewMs = Math.abs(apiTime - midpoint);
  const dbSkewMs = Number(databaseDetail?.clockSkewMs);
  const clocksOk =
    Number.isFinite(apiSkewMs) &&
    apiSkewMs <= 30_000 &&
    Number.isFinite(dbSkewMs) &&
    dbSkewMs <= 30_000;
  checks.push({
    name: "ops:api-database-clock-skew",
    ok: clocksOk || !strict,
    detail: JSON.stringify({ apiSkewMs: Math.round(apiSkewMs), databaseSkewMs: dbSkewMs }),
  });
}
