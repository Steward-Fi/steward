/** Deployment environment wiring for governed provider authority. */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..", "..");
const COMPOSE = join(ROOT, "deploy", "enterprise-reference", "docker-compose.yml");
const ROOT_COMPOSE = join(ROOT, "docker-compose.yml");
const DEPLOY_COMPOSE = join(ROOT, "deploy", "docker-compose.yml");
const COMPOSE_FILES = [ROOT_COMPOSE, DEPLOY_COMPOSE, COMPOSE];
const INIT = join(ROOT, "packages", "cli", "src", "init.ts");
const DOCTOR = join(ROOT, "packages", "cli", "src", "doctor.ts");

function composeService(path: string, service: string): string {
  const lines = readFileSync(path, "utf8").split("\n");
  const start = lines.indexOf(`  ${service}:`);
  if (start < 0) throw new Error(`missing ${service} service in ${path}`);
  const end = lines.findIndex((line, index) => index > start && /^ {2}[A-Za-z0-9_-]+:$/.test(line));
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

describe("provider authority deployment environment", () => {
  test("enterprise compose requires execution and audit signing secrets", () => {
    const compose = readFileSync(COMPOSE, "utf8");
    // The `${VAR:?required}` form makes Compose stop before an unsafe boot.
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

  test("every production compose passes Google provider credentials to API and proxy", () => {
    for (const path of COMPOSE_FILES) {
      const compose = readFileSync(path, "utf8");
      expect(compose.match(/^\s+GOOGLE_PROVIDER_CLIENT_ID:/gm)).toHaveLength(2);
      expect(compose.match(/^\s+GOOGLE_PROVIDER_CLIENT_SECRET:/gm)).toHaveLength(2);
    }
  });
});
