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
 * It imports the generated contract directly — no server is started and no DB is
 * touched.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const { OPENAPI_DOC: document } = await import("../src/openapi");

// Server URL for the DOCS-SITE copy (Mintlify).
//
// The runtime spec (getOpenApiSpec / docs/openapi.json, served by the API at
// /openapi.json) uses a RELATIVE server URL ("/") so generated clients target
// the same origin the spec was fetched from. That is correct there, but WRONG
// for the Mintlify copy: Mintlify serves this file from the docs domain
// (docs.steward.fi), so a relative "/" would make the API playground resolve
// requests against the docs site instead of a Steward instance.
//
// Steward is self-host-first (no shared hosted API), so the docs playground
// points at an explicit self-host example the reader replaces with their own
// deployment URL.
const docsDocument = {
  ...document,
  servers: [
    {
      url: "http://localhost:3200",
      description:
        "Your self-hosted Steward instance (Steward is self-host-first; replace with your deployment URL). The playground targets this rather than the docs domain.",
    },
  ],
};
const runtimeJson = `${JSON.stringify(document, null, 2)}\n`;
const docsJson = `${JSON.stringify(docsDocument, null, 2)}\n`;

// The route definitions in packages/api are the source of truth. Emit both the
// runtime document and the Mintlify copy in one operation so neither committed
// artifact can drift; only the docs copy overrides the `servers` block.
const runtimeSpecPath = join(import.meta.dir, "..", "..", "..", "docs", "openapi.json");
const docsSpecPath = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "docs",
  "api-reference",
  "openapi.json",
);
mkdirSync(dirname(runtimeSpecPath), { recursive: true });
mkdirSync(dirname(docsSpecPath), { recursive: true });
writeFileSync(runtimeSpecPath, runtimeJson);
writeFileSync(docsSpecPath, docsJson);
console.log(`[openapi] wrote ${runtimeSpecPath}`);
console.log(`[openapi] wrote ${docsSpecPath}`);

const pathCount = Object.keys(document.paths ?? {}).length;
console.log(`[openapi] ${pathCount} documented path(s)`);

// The app import opens an in-memory PGLite handle (and the app registers GC
// timers on some runtimes) that keep the event loop alive. The document is fully
// written above, so exit explicitly rather than hang.
process.exit(0);
