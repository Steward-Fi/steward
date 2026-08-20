/** Deployment environment wiring for governed provider authority. */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..", "..");
const COMPOSE = join(ROOT, "deploy", "enterprise-reference", "docker-compose.yml");
const ROOT_COMPOSE = join(ROOT, "docker-compose.yml");
const DEV_COMPOSE = join(ROOT, "docker-compose.dev.yml");
const DEPLOY_COMPOSE = join(ROOT, "deploy", "docker-compose.yml");
const RAILWAY_GUIDE = join(ROOT, "docs", "RAILWAY-DEPLOY.md");
const CLOUDFLARE_GUIDE = join(ROOT, "packages", "api", "CLOUDFLARE.md");
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

  test("compose profiles wire only the canonical JWT signing secret", () => {
    for (const [path, services] of [
      [ROOT_COMPOSE, ["steward-api", "steward-proxy"]],
      [DEV_COMPOSE, ["steward-api", "steward-proxy"]],
      [DEPLOY_COMPOSE, ["steward", "steward-proxy"]],
      [COMPOSE, ["steward-api", "steward-proxy"]],
    ] as const) {
      for (const service of services) {
        const source = composeService(path, service);
        expect(source).toContain("STEWARD_JWT_SECRET:");
        expect(source).not.toContain("STEWARD_SESSION_SECRET:");
      }
    }
  });

  test("deployment guides keep JWT signing material server-side", () => {
    for (const path of [
      join(ROOT, "README.md"),
      join(ROOT, "deploy", "README.md"),
      RAILWAY_GUIDE,
      CLOUDFLARE_GUIDE,
    ]) {
      expect(readFileSync(path, "utf8")).toContain("STEWARD_JWT_SECRET");
    }

    const railwayGuide = readFileSync(RAILWAY_GUIDE, "utf8");
    const frontendSection =
      railwayGuide.match(/## 8\. Connect to Eliza Cloud[\s\S]*?(?=\n## )/)?.[0] ?? "";
    expect(frontendSection).not.toBe("");
    expect(frontendSection).not.toMatch(/STEWARD_(?:JWT|SESSION)_SECRET\s*=/);
    expect(frontendSection).toContain("Do not add `STEWARD_JWT_SECRET`");
    expect(frontendSection).toContain("STEWARD_API_KEY=<tenant apiKey from step 7>");
    expect(frontendSection).not.toContain("STEWARD_AGENT_TOKEN=");
    expect(frontendSection).not.toMatch(
      /NEXT_PUBLIC_(?:STEWARD_API_KEY|STEWARD_AGENT_TOKEN|STEWARD_JWT_SECRET|STEWARD_SESSION_SECRET)\s*=/,
    );
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
