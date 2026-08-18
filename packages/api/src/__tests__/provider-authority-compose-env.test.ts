/** Deployment environment wiring for governed provider authority. */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..", "..");
const COMPOSE = join(ROOT, "deploy", "enterprise-reference", "docker-compose.yml");
const ROOT_COMPOSE = join(ROOT, "docker-compose.yml");
const DEPLOY_COMPOSE = join(ROOT, "deploy", "docker-compose.yml");
const INIT = join(ROOT, "packages", "cli", "src", "init.ts");
const DOCTOR = join(ROOT, "packages", "cli", "src", "doctor.ts");

function composeService(path: string, service: string): string {
  const lines = readFileSync(path, "utf8").split("\n");
  const start = lines.indexOf(`  ${service}:`);
  if (start < 0) throw new Error(`missing ${service} service in ${path}`);
  const end = lines.findIndex((line, index) => index > start && /^ {2}[A-Za-z0-9_-]+:$/.test(line));
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

describe("governed-route environment wiring", () => {
  test("enterprise compose declares execution and audit signing secrets as required", () => {
    const compose = readFileSync(COMPOSE, "utf8");
    // The `${VAR:?required}` form fails compose boot loudly if unset (U10).
    expect(compose).toContain(
      'STEWARD_EXECUTION_AUTH_SECRET: "${STEWARD_EXECUTION_AUTH_SECRET:?required}"',
    );
    expect(compose).toContain(
      'STEWARD_AUDIT_SIGNING_KEY: "${STEWARD_AUDIT_SIGNING_KEY:?required}"',
    );
  });

  test("all API compose profiles pass provider-account X credentials", () => {
    for (const [path, service] of [
      [ROOT_COMPOSE, "steward-api"],
      [DEPLOY_COMPOSE, "steward"],
      [COMPOSE, "steward-api"],
    ] as const) {
      const apiService = composeService(path, service);
      expect(apiService).toContain('X_CLIENT_ID: "${X_CLIENT_ID:-}"');
      expect(apiService).toContain('X_CLIENT_SECRET: "${X_CLIENT_SECRET:-}"');
    }
  });

  test("steward init generates the execution-auth secret", () => {
    const init = readFileSync(INIT, "utf8");
    expect(init).toContain("STEWARD_EXECUTION_AUTH_SECRET=");
  });

  test("steward doctor requires the execution-auth secret", () => {
    const doctor = readFileSync(DOCTOR, "utf8");
    expect(doctor).toContain('"STEWARD_EXECUTION_AUTH_SECRET"');
    expect(doctor).toContain("strict:governed-route-prerequisites");
  });
});
