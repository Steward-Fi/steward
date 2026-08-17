#!/usr/bin/env node
/**
 * Production deploy environment guard (SEC-076).
 *
 * The e2e-only escape hatch `E2E_ALLOW_INSECURE_HTTP` strips HSTS and CSP
 * `upgrade-insecure-requests` from the build output. Because the flag is
 * resolved at BUILD time, a wrong-env production build would silently ship
 * without HTTPS enforcement. The production deploy pipeline (cf:build,
 * cf:preview, cf:deploy) runs this script first and refuses to proceed.
 */

const failures = [];

if (process.env.E2E_ALLOW_INSECURE_HTTP === "true") {
  failures.push(
    "E2E_ALLOW_INSECURE_HTTP is set — this e2e-only flag disables HTTPS enforcement (HSTS + CSP upgrade-insecure-requests) and must never be present in a production deploy.",
  );
}

if (failures.length > 0) {
  console.error("Refusing to build/deploy for production:\n");
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  console.error("\nUnset the flagged variable(s) and retry.");
  process.exit(1);
}
