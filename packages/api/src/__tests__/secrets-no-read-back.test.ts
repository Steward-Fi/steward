/**
 * secrets-no-read-back.test.ts — static proof that the /secrets HTTP surface
 * cannot return a plaintext secret value. SecretVault is the canonical
 * sovereign-custody plane.
 *
 * The property: once stored, NO API path returns a secret's plaintext. Secrets
 * are write + exercise only — values enter via POST/PUT/rotate and are consumed
 * exclusively in-process (proxy credential injection, provider refresh), never
 * read back by a caller.
 *
 * Technique: byte-level scan of the route source (same as secrets-audit-order
 * and secret-routes-validation), asserting the structural invariants:
 *
 *   1. The routes module never imports or calls the decrypt methods.
 *   2. Every success response body is built from SecretMetadata/route shapes;
 *      the only place a request's `value` appears is as validated INPUT.
 *   3. There is no GET route that could carry a value (`/:id` returns
 *      metadata via getSecretById, which the vault-side no-read-back test
 *      proves is value-free).
 */

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "secrets.ts"), "utf8");

/** Strip comments so scans hit real code only. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, (_m, p1) => p1);
}

const code = stripComments(routeSource);

describe("/secrets no-read-back surface", () => {
  it("never imports or calls a decrypt method", () => {
    expect(code).not.toContain("decryptSecret");
    expect(code).not.toContain("decryptSecretRow");
    expect(code).not.toContain("exerciseSecret");
  });

  it("request `value` fields are input-only: validated, passed to the vault, never echoed", () => {
    // Every use of a body value must be one of: presence/type validation,
    // line-break validation, or a vault write call. It must never appear inside
    // a c.json(...) response construction.
    const responseBlocks = [...code.matchAll(/c\.json<ApiResponse>\(\s*\{[^}]*\}/g)].map(
      (m) => m[0],
    );
    expect(responseBlocks.length).toBeGreaterThan(10);
    for (const block of responseBlocks) {
      expect(block).not.toContain("body.value");
      expect(block).not.toContain("value:");
    }
  });

  it("success responses carry vault metadata/route objects, not raw strings from the request", () => {
    // The data payloads returned by the secret CRUD surface are exactly the
    // vault-returned metadata objects (secret / rotated / list) or deletion
    // acknowledgements — shapes the vault-side no-read-back test proves are
    // value-free.
    expect(code).toContain("{ ok: true, data: secret }");
    expect(code).toContain("{ ok: true, data: rotated }");
    expect(code).toContain("{ ok: true, data: list }");
    expect(code).toContain("{ ok: true, data: { deleted: secretId } }");
  });

  it("has no reveal/export/value read route", () => {
    for (const forbidden of ["/reveal", "/export", "/value", "/plaintext", "/decrypt"]) {
      expect(code).not.toContain(`"${forbidden}"`);
      expect(code).not.toContain(`"/:id${forbidden}"`);
    }
    // GET routes on this surface: collection list, route list, and metadata by
    // id. A new GET must be classified against the no-read-back property.
    const getRoutes = [...code.matchAll(/secretsRoutes\.get\(\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(getRoutes.sort()).toEqual(["/", "/:id", "/routes"]);
  });

  it("keeps no-store caching on every response (secret inventory is not cacheable)", () => {
    expect(code).toContain('secretsRoutes.use("*"');
    expect(code).toContain("setNoStoreHeaders(c)");
  });
});
