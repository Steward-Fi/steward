/**
 * openapi.ts — Schema-driven OpenAPI infrastructure.
 *
 * Steward's route contracts were historically described three independent,
 * hand-synced ways (inline zod in handlers, prose Mintlify `.mdx`, and a
 * hand-mirrored SDK type file) with nothing derived from the others — so they
 * drift. This module makes the *handler the single source of truth*: a route is
 * declared once with `createRoute` + zod schemas, which simultaneously (1) drive
 * request validation, (2) type the handler's responses, and (3) emit the OpenAPI
 * document that the SDK types and published docs are generated from.
 *
 * Migration is incremental. The root app and any migrated route module are built
 * with {@link createOpenAPIApp}; routes still written as plain `app.get/post`
 * keep working unchanged and simply do not (yet) appear in the spec. Convert them
 * one at a time — see `routes/trade.ts` for the reference pattern.
 */

import { OpenAPIHono, z } from "@hono/zod-openapi";
import type { ApiResponse, AppVariables } from "./services/context";

export { createRoute, z } from "@hono/zod-openapi";

/**
 * Construct an OpenAPI-aware Hono app pre-wired with Steward's `AppVariables` and
 * a shared validation hook. Drop-in superset of `new Hono<{ Variables }>()` — use
 * it for the root app and every migrated route module.
 *
 * The hook maps a failed zod parse onto Steward's existing error envelope
 * (`{ ok: false, error }`, HTTP 400) so migrating a route to schema validation
 * does not change the shape or status code clients already depend on.
 */
export function createOpenAPIApp() {
  return new OpenAPIHono<{ Variables: AppVariables }>({
    defaultHook: (result, c) => {
      if (!result.success) {
        const message = result.error?.issues?.[0]?.message ?? "Invalid request";
        return c.json<ApiResponse>({ ok: false, error: message }, 400);
      }
    },
  });
}

// ─── Shared response-envelope schemas ────────────────────────────────────────
// Steward wraps successful payloads in `{ ok: true, data }` and errors in
// `{ ok: false, error }`. These helpers keep migrated routes consistent with that
// contract while making the `data` shape explicit in the spec.

/** `{ ok: true, data: <schema> }` */
export function okEnvelope<T extends z.ZodTypeAny>(data: T) {
  return z.object({ ok: z.literal(true), data });
}

/** `{ ok: false, error: string }` */
export const errorEnvelope = z
  .object({ ok: z.literal(false), error: z.string() })
  .openapi("ErrorResponse");

/**
 * Typed envelope constructors. Using these in a migrated handler yields the exact
 * literal types (`ok: true`/`ok: false`) the OpenAPI response schemas expect, so
 * `c.json(ok(data), 200)` / `c.json(err(msg), 400)` typecheck without per-call
 * `as const`. Behaviourally identical to the existing `{ ok, data }`/`{ ok, error }`.
 */
export function ok<const T>(data: T): { ok: true; data: T } {
  return { ok: true, data };
}

export function err(error: string): { ok: false; error: string } {
  return { ok: false, error };
}

/** Standard JSON request/response content wrapper for a schema. */
export function jsonContent<T extends z.ZodTypeAny>(schema: T, description: string) {
  return { content: { "application/json": { schema } }, description };
}

// ─── Document metadata ───────────────────────────────────────────────────────

export const OPENAPI_DOC = {
  openapi: "3.1.0",
  info: {
    title: "Steward API",
    version: "0.4.4",
    description:
      "Open-source agent & application wallet infrastructure. This document is " +
      "generated from the route definitions and is the single source of truth for " +
      "the SDK types and reference docs.",
  },
  servers: [{ url: "https://api.steward.fi", description: "Production" }],
};

/**
 * Whether the live `/openapi.json` endpoint should be served. The spec is always
 * generated at build time for the SDK and docs; the *live* endpoint is opt-in — a
 * custody API should not expose its surface publicly by default.
 *
 * FAIL CLOSED on an unknown runtime: the Cloudflare Workers production target does
 * NOT set `NODE_ENV`, so a `!== "production"` default would serve the spec publicly
 * there. We auto-enable ONLY for an explicitly non-production `NODE_ENV`
 * (local dev / `bun test`); everything else requires `STEWARD_OPENAPI_ENABLED=1`.
 * On Workers the value is read per-isolate, so the toggle takes effect on
 * (re)deploy. Human-readable docs are served by the Mintlify site, not in-app.
 */
export function isOpenApiHttpEnabled(): boolean {
  if (process.env.STEWARD_OPENAPI_ENABLED === "1") return true;
  if (process.env.STEWARD_OPENAPI_ENABLED === "0") return false;
  return process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";
}
