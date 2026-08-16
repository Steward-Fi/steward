/**
 * PR6 compose/init/doctor governed-route env verification (§4 / G2).
 *
 * PR4 already wired STEWARD_EXECUTION_AUTH_SECRET into compose + init + doctor;
 * PR6 VERIFIES presence (does NOT double-add). This is a source-scan regression
 * guard: if a later change drops the required fail-closed env from the
 * enterprise-reference compose, the golden path would boot without the governed
 * dispatch secret. This test fails closed on that regression.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..", "..", "..", "..");
const COMPOSE = join(ROOT, "deploy", "enterprise-reference", "docker-compose.yml");
const INIT = join(ROOT, "packages", "cli", "src", "init.ts");
const DOCTOR = join(ROOT, "packages", "cli", "src", "doctor.ts");

describe("PR6 governed-route env wiring (verify-only, G2)", () => {
  test("compose declares the PR4 exec-auth + PR5 audit signing secrets as REQUIRED", () => {
    const compose = readFileSync(COMPOSE, "utf8");
    // The `${VAR:?required}` form fails compose boot loudly if unset (U10).
    expect(compose).toContain(
      'STEWARD_EXECUTION_AUTH_SECRET: "${STEWARD_EXECUTION_AUTH_SECRET:?required}"',
    );
    expect(compose).toContain(
      'STEWARD_AUDIT_SIGNING_KEY: "${STEWARD_AUDIT_SIGNING_KEY:?required}"',
    );
  });

  test("steward init generates the PR4 execution-auth secret", () => {
    const init = readFileSync(INIT, "utf8");
    expect(init).toContain("STEWARD_EXECUTION_AUTH_SECRET=");
  });

  test("steward doctor requires the PR4 execution-auth secret", () => {
    const doctor = readFileSync(DOCTOR, "utf8");
    expect(doctor).toContain('"STEWARD_EXECUTION_AUTH_SECRET"');
    // And the PR6 strict governed-route prerequisite gate is present.
    expect(doctor).toContain("strict:governed-route-prerequisites");
  });
});
