/**
 * capture-payload.ts - the typed CONTRACT for a captured browser-session jar.
 *
 * this is the zod schema for exactly what the slice-1 capture extension emits
 * from `packageJar()` ({ jar: Cookie[], metadata: {...} }). it is the typed
 * replacement for the extension mock-receiver's untyped request body, so a
 * future real capture receiver (session-handoff #157, slice 3) can parse the
 * push with a single source of truth and drift is caught by the contract test.
 *
 * SCOPE / WHAT THIS DELIBERATELY DOES *NOT* DO (read before extending):
 *   - it commits to NO ingress architecture. sealed-to-enclave vs plaintext
 *     push is slice 2's decision; this schema is identical either way (it types
 *     the *shape* of the jar, not how/where it is decrypted). see
 *     `~/.moltbot/projects/steward/SLICE3-CAPTURE-CAPABILITY-GRANT-WIRING.md` §4.5.
 *   - it adds NO tables, NO migrations, NO routes, NO receiver endpoint. it is a
 *     pure type + a safe/loggable view helper. it does not touch the invoke /
 *     proxy / policy decision paths.
 *   - it is ENV-FREE. the #158 fail-closed cookie gate (STEWARD_ALLOW_COOKIE_INJECTION)
 *     and the host allowlist are enforced by the SHARED secret-route validator at
 *     capability/route create time (see validate.ts / @stwd/vault). a pure payload
 *     schema needs no flag - it types what the extension sends; the governors run
 *     later, when that payload is turned into a capability + route. keeping this
 *     schema flag-free means it is safe to import anywhere (tests, tooling) with
 *     no environment coupling.
 *
 * FIDELITY DISCIPLINE (mirrors jar.js PRESERVED_ATTRS): cookie attributes are
 * OPTIONAL, never defaulted. the extension omits an attribute when chrome did
 * not report it (e.g. a session cookie has no `expirationDate`) rather than
 * emitting a lie like `httpOnly:false`. the schema MUST therefore accept an
 * entry with only `name`+`value` present and MUST NOT coerce a missing attr to
 * a default - otherwise a re-injected jar would carry attributes the site never
 * set and could trip integrity checks. `name` and `value` are the only required
 * cookie fields.
 */

import { z } from "zod";

/**
 * chrome.cookies.SameSiteStatus. the extension passes through whatever chrome
 * reports; the observed set is exactly these four. pinned as an enum so a typo
 * or an unexpected value (e.g. a browser that renamed the field) is rejected
 * rather than silently injected. matched against the slice-1 fixtures
 * (`no_restriction`, `lax`) plus chrome's other documented values.
 */
export const sameSiteSchema = z.enum(["no_restriction", "lax", "strict", "unspecified"]);

/**
 * one captured cookie. mirrors jar.js `PRESERVED_ATTRS` / `normalizeCookie`
 * EXACTLY - if that list changes, this schema (and the contract test's pinned
 * field list) must change with it. `.strict()` so an unexpected attribute the
 * extension never emits is a loud failure, not a silent pass-through into the
 * secret value.
 *
 * required: `name`, `value` (a cookie with no name or no value is not a cookie).
 * everything else is optional + never defaulted (fidelity discipline above).
 */
export const capturedCookieSchema = z
  .object({
    name: z.string().min(1),
    // NOTE: value may be an empty string for some cookies; only `name` needs a
    // min length. a MISSING value, however, is rejected (a cookie must carry a
    // value field to be a credential worth capturing).
    value: z.string(),
    domain: z.string().min(1).optional(),
    path: z.string().min(1).optional(),
    secure: z.boolean().optional(),
    httpOnly: z.boolean().optional(),
    sameSite: sameSiteSchema.optional(),
    expirationDate: z.number().optional(),
    hostOnly: z.boolean().optional(),
    session: z.boolean().optional(),
    storeId: z.string().optional(),
  })
  .strict();

export type CapturedCookie = z.infer<typeof capturedCookieSchema>;

/**
 * the TTL of the grant a captured jar will drive. matches jar.js metadata.ttl
 * ('1h' | '24h' | '7d' | 'until-revoked'). pinned as an enum so a garbage ttl
 * (e.g. "forever", "-1") is rejected at the contract boundary rather than
 * flowing into a grant's expiry math.
 */
export const captureTtlSchema = z.enum(["1h", "24h", "7d", "until-revoked"]);

/**
 * the consented scope. mirrors jar.js metadata.scope: BOTH `read` and `write`
 * are required booleans (the human consented to a specific pair; a missing side
 * is ambiguous and rejected). attenuation itself lives in Steward policy, not
 * the jar - this only records what was consented to.
 */
export const captureScopeSchema = z
  .object({
    read: z.boolean(),
    write: z.boolean(),
  })
  .strict();

/**
 * the capture metadata block. mirrors jar.js `packageJar()` metadata EXACTLY.
 * `originUA` is nullable (jar.js defaults it to `null` when absent - the one
 * field the extension DOES default, deliberately, because a null UA is a
 * meaningful "unknown" not a lie). `cookieCount` is present in the emitted
 * payload; it is validated but is NOT trusted as authoritative over
 * `jar.length` (a real receiver recomputes counts server-side - see the
 * redaction discipline in the contract test).
 */
export const captureMetadataSchema = z
  .object({
    domain: z.string().min(1),
    capturedAt: z.string().min(1),
    ttl: captureTtlSchema,
    scope: captureScopeSchema,
    originUA: z.string().nullable(),
    captureMethod: z.string().min(1),
    // provenance channel tag (jar.js sets 'PROTOTYPE-plaintext-localhost').
    // optional so the schema does not lock the prototype tag as permanent - a
    // sealed-channel push (slice 2) will set a different channel string.
    channel: z.string().min(1).optional(),
    cookieCount: z.number().int().nonnegative(),
  })
  .strict();

export type CaptureMetadata = z.infer<typeof captureMetadataSchema>;

/**
 * the full capture payload: exactly the `{ jar, metadata }` object `packageJar()`
 * returns.
 *
 * EMPTY-JAR DECISION (pinned): an empty `jar` is REJECTED (min 1). rationale
 * (spec §4.4 / §1.1): a captured session with zero cookies has nothing to
 * serialize into a secret and nothing to inject - it cannot produce a usable
 * capability. rejecting it at the contract boundary fails closed instead of
 * minting a credential that would inject an empty Cookie header. (the extension
 * only reaches packageJar after detectSession finds >=1 session cookie, so a
 * zero-length jar here signals a bug or a tampered push, not a legitimate
 * capture.) `.strict()` at the top level rejects any unexpected top-level key.
 */
export const capturePayloadSchema = z
  .object({
    jar: z.array(capturedCookieSchema).min(1, "jar must contain at least one cookie"),
    metadata: captureMetadataSchema,
  })
  .strict();

export type CapturePayload = z.infer<typeof capturePayloadSchema>;

/**
 * the exact ordered field list `jar.js` PRESERVED_ATTRS emits per cookie. the
 * contract test pins the schema's accepted cookie keys against THIS constant so
 * a drift on either side (extension adds/removes an attr, or the schema does) is
 * caught. keep in lockstep with jar.js PRESERVED_ATTRS.
 */
export const CAPTURED_COOKIE_FIELDS = [
  "name",
  "value",
  "domain",
  "path",
  "secure",
  "httpOnly",
  "sameSite",
  "expirationDate",
  "hostOnly",
  "session",
  "storeId",
] as const;

/**
 * a SAFE / loggable view of a capture payload: cookie NAMES + counts only,
 * NEVER values. server-side twin of the extension's jar.js `redactJar` /
 * mock-receiver `redact`, duplicated here so a Steward-side consumer never has
 * to trust the client to have redacted, and never risks serializing a value
 * into a log/telemetry/audit field.
 *
 * INVARIANT (asserted in the contract test): the returned object contains NO
 * cookie `value`. it carries names, counts, and non-secret metadata only. this
 * is the ONLY view of a capture payload that is safe to log, echo, or write to
 * an audit event.
 *
 * takes a PARSED payload (run it through capturePayloadSchema first) so the
 * shape is guaranteed.
 */
export function redactCapturePayload(payload: CapturePayload): {
  domain: string;
  capturedAt: string;
  ttl: CaptureMetadata["ttl"];
  scope: CaptureMetadata["scope"];
  captureMethod: string;
  channel: string | undefined;
  cookieCount: number;
  cookieNames: string[];
  httpOnlyCount: number;
} {
  const { jar, metadata } = payload;
  return {
    domain: metadata.domain,
    capturedAt: metadata.capturedAt,
    ttl: metadata.ttl,
    scope: metadata.scope,
    captureMethod: metadata.captureMethod,
    channel: metadata.channel,
    // recompute from the jar, do NOT trust metadata.cookieCount as authoritative.
    cookieCount: jar.length,
    // names ONLY - never values.
    cookieNames: jar.map((c) => c.name),
    httpOnlyCount: jar.filter((c) => c.httpOnly === true).length,
  };
}
