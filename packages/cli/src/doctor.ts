import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { StewardApiClient } from "./api";
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
  }

  const api = options.api ?? new StewardApiClient({ baseUrl: env.STEWARD_API_URL });
  try {
    const health = await api.request("GET", "/health", undefined, { tenant: false });
    checks.push({ name: "api:/health", ok: true, detail: JSON.stringify(health) });
  } catch (error) {
    checks.push({ name: "api:/health", ok: !options.strict, detail: (error as Error).message });
  }
  try {
    const ready = await api.request("GET", "/ready", undefined, { tenant: false });
    checks.push({ name: "api:/ready", ok: true, detail: JSON.stringify(ready) });
  } catch (error) {
    checks.push({ name: "api:/ready", ok: !options.strict, detail: (error as Error).message });
  }

  return { ok: checks.every((check) => check.ok), checks };
}
