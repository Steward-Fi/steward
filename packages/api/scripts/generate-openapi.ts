#!/usr/bin/env bun
/**
 * Emit the OpenAPI 3.1 document from the live route definitions.
 *
 * The route `createRoute` declarations in `src/routes/*` are the single source of
 * truth; this script renders them to `openapi.json` (consumed by the SDK type
 * generator) and copies it to `docs/api-reference/openapi.json` (consumed by
 * Mintlify). Run it whenever a route's schema changes:
 *
 *   bun scripts/generate-openapi.ts        # or: bun run openapi:generate
 *
 * It imports the app for its route table only — no server is started and no DB is
 * touched (the document is built purely from the registered schemas).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// `src/services/context.ts` resolves several invariants at module-init time
// (DATABASE_URL / master password) and eagerly runs a default-tenant insert, so
// importing the app for its route table needs the same deterministic bootstrap
// the test suite uses: an in-memory PGLite + full-entropy placeholder secrets.
// The document is built purely from the registered route schemas — nothing here
// reaches production data. All values use `??=`, so a real environment is never
// overridden.
process.env.NODE_ENV ??= "development";
process.env.STEWARD_DB_MODE ??= "pglite";
process.env.STEWARD_PGLITE_MEMORY ??= "true";
process.env.STEWARD_MASTER_PASSWORD ??= "openapi-doc-generation-placeholder-secret";
process.env.STEWARD_JWT_SECRET ??=
  "openapi-doc-generation-placeholder-jwt-secret-with-enough-entropy-0123456789";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "0".repeat(64);

if (!process.env.DATABASE_URL) {
  const { createPGLiteDb, setPGLiteOverride } = await import("@stwd/db/pglite");
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
}

const { app } = await import("../src/app");
const { OPENAPI_DOC } = await import("../src/openapi");

const document = app.getOpenAPI31Document(OPENAPI_DOC);
const json = `${JSON.stringify(document, null, 2)}\n`;

// Single canonical artifact. The route definitions in packages/api are the source
// of truth; this emitted spec is the one committed copy, consumed by both Mintlify
// (docs site) and the SDK type generator. No second copy to drift.
const specPath = join(import.meta.dir, "..", "..", "..", "docs", "api-reference", "openapi.json");
mkdirSync(dirname(specPath), { recursive: true });
writeFileSync(specPath, json);
console.log(`[openapi] wrote ${specPath}`);

const pathCount = Object.keys(document.paths ?? {}).length;
console.log(`[openapi] ${pathCount} documented path(s)`);

// The app import opens an in-memory PGLite handle (and the app registers GC
// timers on some runtimes) that keep the event loop alive. The document is fully
// written above, so exit explicitly rather than hang.
process.exit(0);
