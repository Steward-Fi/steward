#!/usr/bin/env bun
/**
 * Generate the SDK's API types from the OpenAPI document.
 *
 * Replaces hand-mirroring `@stwd/shared` types into `@stwd/sdk` by mistake-prone
 * copy: the request/response types here are derived from the same spec that the
 * server validates against, so they cannot silently drift. Run after
 * `generate-openapi.ts`:
 *
 *   bun scripts/generate-sdk-types.ts      # or: bun run sdk:types
 *
 * Output: `packages/sdk/src/generated/api-types.ts` (do not edit by hand).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import openapiTS, { astToString } from "openapi-typescript";

const specPath = join(import.meta.dir, "..", "openapi.json");
const outPath = join(import.meta.dir, "..", "..", "sdk", "src", "generated", "api-types.ts");

const ast = await openapiTS(new URL(`file://${specPath}`), {
  // Treat schema-less responses as unknown rather than `never`.
  emptyObjectsUnknown: true,
});

const banner =
  "/**\n" +
  " * GENERATED FILE — do not edit by hand.\n" +
  " * Produced by packages/api/scripts/generate-sdk-types.ts from the OpenAPI\n" +
  " * document (packages/api/openapi.json). Run `bun run openapi:generate` in\n" +
  " * @stwd/api to regenerate after a route schema changes.\n" +
  " */\n\n";

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, banner + astToString(ast));
console.log(`[sdk-types] wrote ${outPath}`);
