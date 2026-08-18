/**
 * Split a PostgreSQL URI into a credential-free URI and a password file.
 *
 * The URI arrives through DATABASE_URL (never argv). The password file path is
 * a caller-created mode-0600 temporary file. Supporting both userinfo and the
 * libpq `?password=` connection parameter keeps every valid password-bearing
 * URI out of psql's process argv.
 */
import { writeFileSync } from "node:fs";

const raw = process.env.DATABASE_URL;
// biome-ignore lint/suspicious/noUndeclaredEnvVars: ephemeral file path for this standalone CLI helper, never a Turbo cache input
const passwordFile = process.env.STEWARD_PSQL_PASSWORD_FILE;
if (!raw || !passwordFile) {
  throw new Error("DATABASE_URL and STEWARD_PSQL_PASSWORD_FILE are required");
}

const schemeMatch = /^(postgres(?:ql)?):\/\//.exec(raw);
if (!schemeMatch) {
  throw new Error("DATABASE_URL must use postgres:// or postgresql://");
}

if (/[\0\r\n]/.test(raw)) {
  throw new Error("DATABASE_URL contains an unsupported control character");
}
if (raw.includes("#")) throw new Error("DATABASE_URL must not contain a fragment");

const schemeEnd = schemeMatch[0].length;
const rawQueryStart = raw.indexOf("?", schemeEnd);
const hierarchyEnd = rawQueryStart === -1 ? raw.length : rawQueryStart;
const hierarchy = raw.slice(0, hierarchyEnd);
const authorityEndCandidate = hierarchy.indexOf("/", schemeEnd);
const authorityEnd = authorityEndCandidate === -1 ? hierarchy.length : authorityEndCandidate;
const authority = hierarchy.slice(schemeEnd, authorityEnd);

// Do not feed the URI through WHATWG URL. Valid libpq URIs include multi-host
// authorities and percent-encoded Unix-socket hosts, both of which WHATWG URL
// rejects or normalizes. Instead, remove only the userinfo password and retain
// every other byte for libpq itself to parse.
const at = authority.indexOf("@");
if (at !== authority.lastIndexOf("@")) {
  throw new Error("DATABASE_URL contains ambiguous user information");
}

let password = "";
let redactedAuthority = authority;
if (at !== -1) {
  const userInfo = authority.slice(0, at);
  const passwordSeparator = userInfo.indexOf(":");
  if (passwordSeparator !== -1) {
    password = decodeURIComponent(userInfo.slice(passwordSeparator + 1));
    redactedAuthority = `${userInfo.slice(0, passwordSeparator)}@${authority.slice(at + 1)}`;
  }
}

// libpq accepts connection keywords in the URI query string. A query password
// takes precedence over userinfo because it is parsed later by libpq. Preserve
// every other query token byte-for-byte: WHATWG URLSearchParams would serialize
// `%20` as `+`, but libpq URI parsing does not use HTML form-url-encoding and
// may interpret that as a literal plus.
const rawQuery = rawQueryStart === -1 ? "" : raw.slice(rawQueryStart + 1);
const retainedQueryParts: string[] = [];
let lastNonEmptyQueryPassword: string | undefined;
if (rawQueryStart !== -1) {
  for (const part of rawQuery.split("&")) {
    const separator = part.indexOf("=");
    const rawKey = separator === -1 ? part : part.slice(0, separator);
    const rawValue = separator === -1 ? "" : part.slice(separator + 1);
    if (decodeURIComponent(rawKey) === "password") {
      const queryPassword = decodeURIComponent(rawValue);
      // libpq processes parameters from left to right and lets the last
      // non-empty value win. Empty query values therefore do not erase an
      // earlier userinfo password, while duplicate non-empty values retain
      // their documented libpq meaning.
      if (queryPassword.length > 0) lastNonEmptyQueryPassword = queryPassword;
    } else {
      retainedQueryParts.push(part);
    }
  }
}
if (lastNonEmptyQueryPassword !== undefined) password = lastNonEmptyQueryPassword;

if (/[\0\r\n]/.test(password)) {
  throw new Error("DATABASE_URL password contains an unsupported control character");
}

writeFileSync(passwordFile, password, { mode: 0o600 });
const retainedQuery = retainedQueryParts.join("&");
const redactedHierarchy = `${raw.slice(0, schemeEnd)}${redactedAuthority}${hierarchy.slice(authorityEnd)}`;
process.stdout.write(`${redactedHierarchy}${retainedQuery ? `?${retainedQuery}` : ""}`);
