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

const url = new URL(raw);
if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
  throw new Error("DATABASE_URL must use postgres:// or postgresql://");
}

if (url.hash) throw new Error("DATABASE_URL must not contain a fragment");

let password = decodeURIComponent(url.password);
url.password = "";

// libpq accepts connection keywords in the URI query string. A query password
// takes precedence over userinfo because it is parsed later by libpq. Preserve
// every other query token byte-for-byte: WHATWG URLSearchParams would serialize
// `%20` as `+`, but libpq URI parsing does not use HTML form-url-encoding and
// may interpret that as a literal plus.
const rawQueryStart = raw.indexOf("?");
const rawQuery = rawQueryStart === -1 ? "" : raw.slice(rawQueryStart + 1);
const retainedQueryParts: string[] = [];
const queryPasswords: string[] = [];
if (rawQueryStart !== -1) {
  for (const part of rawQuery.split("&")) {
    const separator = part.indexOf("=");
    const rawKey = separator === -1 ? part : part.slice(0, separator);
    const rawValue = separator === -1 ? "" : part.slice(separator + 1);
    if (decodeURIComponent(rawKey) === "password") {
      queryPasswords.push(decodeURIComponent(rawValue));
    } else {
      retainedQueryParts.push(part);
    }
  }
}
if (queryPasswords.length > 1) {
  throw new Error("DATABASE_URL must not contain multiple password parameters");
}
if (queryPasswords.length === 1) {
  password = queryPasswords[0] ?? "";
}

if (/[\0\r\n]/.test(password)) {
  throw new Error("DATABASE_URL password contains an unsupported control character");
}

writeFileSync(passwordFile, password, { mode: 0o600 });
url.search = "";
url.hash = "";
const retainedQuery = retainedQueryParts.join("&");
process.stdout.write(`${url.toString()}${retainedQuery ? `?${retainedQuery}` : ""}`);
