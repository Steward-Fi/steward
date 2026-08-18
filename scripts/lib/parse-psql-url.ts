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

let password = decodeURIComponent(url.password);
url.password = "";

// libpq accepts connection keywords in the URI query string. A query password
// takes precedence over userinfo because it is parsed later by libpq.
if (url.searchParams.has("password")) {
  password = url.searchParams.get("password") ?? "";
  url.searchParams.delete("password");
}

if (/[\0\r\n]/.test(password)) {
  throw new Error("DATABASE_URL password contains an unsupported control character");
}

writeFileSync(passwordFile, password, { mode: 0o600 });
process.stdout.write(url.toString());
