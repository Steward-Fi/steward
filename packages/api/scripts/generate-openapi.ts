#!/usr/bin/env bun
/**
 * Generate both committed OpenAPI documents from the runtime contract.
 *
 * `docs/openapi.json` is byte-for-byte the document served by the API.
 * `docs/api-reference/openapi.json` contains the same paths and schemas with a
 * localhost server URL for Mintlify's interactive explorer.
 */
await import("../../../scripts/generate-openapi.ts");

// Loading the API contract can open runtime handles that keep the event loop
// alive. Both files are fully written once the awaited generator returns.
process.exit(0);
