import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const srcRoot = join(import.meta.dir, "..");

function productionTypescriptFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    if (entry === "__tests__") return [];
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return productionTypescriptFiles(path);
    return entry.endsWith(".ts") ? [path] : [];
  });
}

function directEnvironmentKeys(source: string): string[] {
  const keys = new Set<string>();
  const pattern = /process\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\])/g;
  for (const match of source.matchAll(pattern)) keys.add(match[1] ?? match[2]!);
  return [...keys].sort();
}

// #770 has eliminated direct mutable-global authority from security middleware.
// Keep the exact inventory empty so new readers fail CI instead of silently
// expanding the compatibility bridge.
const pendingMiddlewareReaders = {};

const migratedRuntimeAuthorityKeys = [
  "STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS",
  "STEWARD_REQUEST_EXPIRY_MAX_SKEW_MS",
  "STEWARD_REQUEST_SIGNING_SECRET",
  "STEWARD_REQUEST_SIGNING_SECRETS",
  "STEWARD_REQUEST_TIMESTAMP_TTL_MS",
  "STEWARD_REQUIRE_AUTH_SIGNATURE",
  "STEWARD_REQUIRE_REQUEST_EXPIRY",
  "STEWARD_IDEMPOTENCY_MAX_ENTRIES",
  "STEWARD_IDEMPOTENCY_METRICS_TTL_MS",
  "STEWARD_IDEMPOTENCY_TTL_MS",
  "APP_URL",
  "PASSKEY_ALLOWED_ORIGINS",
  "PASSKEY_ORIGIN",
  "PASSKEY_RP_ID",
  "PASSKEY_RP_NAME",
  "SIWE_ALLOWED_DOMAINS",
  "STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE",
  "STEWARD_OAUTH_ALLOWED_REDIRECTS",
  "STEWARD_OAUTH_REDIRECT_ALLOWLIST",
] as const;

const pendingAuthRouteReaders = [
  "EMAIL_AUTH_REDIRECT_BASE_URL",
  "FARCASTER_LOGIN_ENABLED",
  "NODE_ENV",
  "SMS_PROVIDER",
  "STEWARD_DB_MODE",
  "STEWARD_ENABLE_PROD_TEST_ACCOUNT_TOKEN",
  "STEWARD_PGLITE_MEMORY",
  "TELEGRAM_BOT_TOKEN",
  "TOTP_ISSUER",
  "TWILIO_ACCOUNT_SID",
  "TWILIO_AUTH_TOKEN",
  "TWILIO_FROM",
  "WHATSAPP_OTP_ENABLED",
];

describe("Worker runtime environment static inventory", () => {
  it("rejects unclassified direct process.env readers in security middleware", () => {
    const middlewareRoot = join(srcRoot, "middleware");
    const actual = Object.fromEntries(
      productionTypescriptFiles(middlewareRoot)
        .map((path) => [
          relative(middlewareRoot, path),
          directEnvironmentKeys(readFileSync(path, "utf8")),
        ])
        .filter(([, keys]) => keys.length > 0),
    );
    expect(actual).toEqual(pendingMiddlewareReaders);
  });

  it("keeps migrated runtime authority off mutable process.env globally", () => {
    const violations: string[] = [];
    for (const path of productionTypescriptFiles(srcRoot)) {
      const keys = directEnvironmentKeys(readFileSync(path, "utf8"));
      for (const key of keys) {
        if (
          migratedRuntimeAuthorityKeys.includes(
            key as (typeof migratedRuntimeAuthorityKeys)[number],
          )
        ) {
          violations.push(`${relative(srcRoot, path)}:${key}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("pins the remaining auth-route mutable-global compatibility inventory", () => {
    const authSource = readFileSync(join(srcRoot, "routes", "auth.ts"), "utf8");
    expect(directEnvironmentKeys(authSource)).toEqual(pendingAuthRouteReaders);
    expect(authSource).not.toMatch(/process\.env\s*\[/);
  });
});
