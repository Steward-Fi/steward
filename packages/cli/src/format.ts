export type OutputFormat = "json" | "pretty";

/** Render untrusted text without terminal control sequences or forged lines. */
export function sanitizeTerminalText(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/** Remove exact credentials known to the caller before an error reaches logs. */
export function redactSensitiveText(value: string, secrets: Array<string | undefined>): string {
  let redacted = value;
  const unique = [...new Set(secrets.filter((secret): secret is string => Boolean(secret)))].sort(
    (a, b) => b.length - a.length,
  );
  for (const secret of unique) redacted = redacted.replaceAll(secret, "[REDACTED]");
  return redacted;
}

function isSensitiveOutputKey(key: string): boolean {
  const normalized = key.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  return [
    "token",
    "accesstoken",
    "refreshtoken",
    "claimtoken",
    "pollsecret",
    "secret",
    "clientsecret",
    "credentialsecret",
    "password",
    "apikey",
    "platformkey",
    "tenantkey",
    "privatekey",
    "mnemonic",
    "seedphrase",
  ].some((suffix) => normalized === suffix || normalized.endsWith(suffix));
}

/** Redact secret-shaped response fields before printing API data. */
export function redactForDisplay(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactForDisplay);
  if (!value || typeof value !== "object") return value;
  if (value instanceof Date) return value;
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    output[key] = isSensitiveOutputKey(key) ? "[REDACTED]" : redactForDisplay(child);
  }
  return output;
}

export function printJson(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

export function printResult(value: unknown, format: OutputFormat, allowSensitive = false): void {
  const printable = allowSensitive ? value : redactForDisplay(value);
  if (format === "json") {
    printJson(printable);
    return;
  }
  if (typeof printable === "string") {
    console.log(sanitizeTerminalText(printable));
    return;
  }
  printJson(printable);
}

/**
 * Describe a secret's presence and shape WITHOUT ever emitting any substring of
 * its value. Reports only: present/missing and the byte length. This is safe to
 * print in doctor output (pretty or JSON) and in logs — no portion of the
 * master password, Ed25519 seed, or any other secret is ever revealed.
 *
 * Deliberately never returns the first/last characters of the value: even a
 * handful of leaked chars materially reduces brute-force cost and can identify
 * a rotated-but-reused secret across environments.
 */
export function describeSecret(value: string | undefined): string {
  if (value === undefined || value === "") return "missing";
  const bytes = Buffer.byteLength(value, "utf8");
  return `present (${bytes} bytes)`;
}
