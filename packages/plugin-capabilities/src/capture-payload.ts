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

/** Conservative receiver-side resource limits. Chrome does not expose a single
 * portable cookie-size limit, so these bounds deliberately accept normal
 * browser cookies while preventing a capture request from becoming an
 * unbounded allocation or secret-store write. All byte limits are UTF-8, not
 * JavaScript UTF-16 code-unit counts. */
export const MAX_COOKIE_NAME_BYTES = 256;
export const MAX_COOKIE_VALUE_BYTES = 4096;
export const MAX_COOKIE_PAIR_BYTES = 4096;
export const MAX_COOKIE_COUNT = 180;
export const MAX_CAPTURE_PAYLOAD_BYTES = 256 * 1024;
const MAX_DOMAIN_BYTES = 253;
const MAX_PATH_BYTES = 2048;
const MAX_STORE_ID_BYTES = 128;
const MAX_METADATA_STRING_BYTES = 2048;
const MAX_EXPIRATION_SECONDS = 8_640_000_000_000;

const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).byteLength;

function boundedString(maxBytes: number, label: string, allowEmpty = false) {
  const base = allowEmpty ? z.string() : z.string().min(1);
  return base.refine((value) => utf8ByteLength(value) <= maxBytes, {
    message: `${label} exceeds ${maxBytes} UTF-8 bytes`,
  });
}

const cookieNameSchema = boundedString(MAX_COOKIE_NAME_BYTES, "cookie name")
  .refine(
    (name) => /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name),
    "cookie name must use RFC token characters",
  )
  .refine(
    (name) => !["__proto__", "constructor", "prototype"].includes(name),
    "prototype-like cookie names are not accepted",
  );
const cookieValueSchema = boundedString(MAX_COOKIE_VALUE_BYTES, "cookie value", true);
const domainSchema = boundedString(MAX_DOMAIN_BYTES, "domain").refine((domain) => {
  const hostname = domain.startsWith(".") ? domain.slice(1) : domain;
  return (
    hostname === hostname.toLowerCase() &&
    !hostname.endsWith(".") &&
    hostname.split(".").every((label) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label))
  );
}, "domain must be a canonical lowercase hostname (optional leading dot)");
const pathSchema = boundedString(MAX_PATH_BYTES, "cookie path").refine(
  (path) => path.startsWith("/"),
  "cookie path must start with /",
);

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
const capturedCookieObjectSchema = z
  .object({
    name: cookieNameSchema,
    // NOTE: value may be an empty string for some cookies; only `name` needs a
    // min length. a MISSING value, however, is rejected.
    value: cookieValueSchema,
    domain: domainSchema.optional(),
    path: pathSchema.optional(),
    secure: z.boolean().optional(),
    httpOnly: z.boolean().optional(),
    sameSite: sameSiteSchema.optional(),
    // Chrome reports seconds since epoch and may include millisecond precision.
    expirationDate: z
      .number()
      .finite()
      .nonnegative()
      .max(MAX_EXPIRATION_SECONDS)
      .refine((seconds) => Math.abs(seconds * 1000 - Math.round(seconds * 1000)) < 1e-6, {
        message: "expirationDate supports at most millisecond precision",
      })
      .optional(),
    hostOnly: z.boolean().optional(),
    session: z.boolean().optional(),
    storeId: boundedString(MAX_STORE_ID_BYTES, "storeId", true).optional(),
  })
  .strict()
  .superRefine((cookie, ctx) => {
    if (utf8ByteLength(cookie.name) + utf8ByteLength(cookie.value) > MAX_COOKIE_PAIR_BYTES) {
      ctx.addIssue({
        code: "custom",
        path: ["value"],
        message: `cookie name + value exceeds ${MAX_COOKIE_PAIR_BYTES} UTF-8 bytes`,
      });
    }
    if (cookie.name.startsWith("__Secure-") && cookie.secure !== true) {
      ctx.addIssue({
        code: "custom",
        path: ["secure"],
        message: "__Secure- cookies must be secure",
      });
    }
    if (
      cookie.name.startsWith("__Host-") &&
      (cookie.secure !== true ||
        cookie.path !== "/" ||
        cookie.hostOnly !== true ||
        cookie.domain !== undefined)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "__Host- cookies require secure=true, path=/, hostOnly=true, and no domain",
      });
    }
    if (cookie.hostOnly === true && cookie.domain?.startsWith(".")) {
      ctx.addIssue({
        code: "custom",
        path: ["domain"],
        message: "hostOnly cookie domain cannot start with .",
      });
    }
    if (cookie.session === true && cookie.expirationDate !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["expirationDate"],
        message: "session cookie cannot expire",
      });
    }
  });

export const capturedCookieSchema = z.preprocess((input, ctx) => {
  if (typeof input === "object" && input !== null) {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      if (Object.hasOwn(input, key)) {
        ctx.addIssue({ code: "custom", message: `prototype-like key ${key} is not accepted` });
      }
    }
  }
  return input;
}, capturedCookieObjectSchema);

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
    domain: domainSchema.refine((domain) => !domain.startsWith("."), {
      message: "capture domain cannot start with .",
    }),
    capturedAt: z.iso.datetime({ offset: true, precision: 3 }),
    ttl: captureTtlSchema,
    scope: captureScopeSchema,
    originUA: boundedString(MAX_METADATA_STRING_BYTES, "originUA", true).nullable(),
    captureMethod: boundedString(128, "captureMethod"),
    // provenance channel tag (jar.js sets 'PROTOTYPE-plaintext-localhost').
    // optional so the schema does not lock the prototype tag as permanent - a
    // sealed-channel push (slice 2) will set a different channel string.
    channel: boundedString(128, "channel").optional(),
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
    jar: z
      .array(capturedCookieSchema)
      .min(1, "jar must contain at least one cookie")
      .max(MAX_COOKIE_COUNT, `jar cannot exceed ${MAX_COOKIE_COUNT} cookies`),
    metadata: captureMetadataSchema,
  })
  .strict()
  .superRefine((payload, ctx) => {
    if (payload.metadata.cookieCount !== payload.jar.length) {
      ctx.addIssue({
        code: "custom",
        path: ["metadata", "cookieCount"],
        message: "cookieCount must equal jar length",
      });
    }

    const identities = new Set<string>();
    payload.jar.forEach((cookie, index) => {
      const identity = JSON.stringify([
        cookie.name,
        cookie.domain ?? payload.metadata.domain,
        cookie.path ?? "/",
        cookie.storeId ?? "",
      ]);
      if (identities.has(identity)) {
        ctx.addIssue({
          code: "custom",
          path: ["jar", index],
          message: "duplicate cookie identity (name/domain/path/storeId)",
        });
      }
      identities.add(identity);
    });

    if (utf8ByteLength(JSON.stringify(payload)) > MAX_CAPTURE_PAYLOAD_BYTES) {
      ctx.addIssue({
        code: "custom",
        message: `serialized capture exceeds ${MAX_CAPTURE_PAYLOAD_BYTES} UTF-8 bytes`,
      });
    }
  });

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

// Partitioned and SameParty are intentionally absent because the current
// packageJar/PRESERVED_ATTRS source drops them. Strict parsing fails loudly
// rather than implying replay fidelity that the extension does not provide.

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
