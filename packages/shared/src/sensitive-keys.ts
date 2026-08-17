const SENSITIVE_CREDENTIAL_KEYS = new Set([
  "auth",
  "authorization",
  "cookie",
  "cookieheader",
  "token",
  "secret",
  "credential",
  "apikey",
  "privatekey",
  "password",
  "passphrase",
  "clientsecret",
  "clientsecretvalue",
]);

const SENSITIVE_CREDENTIAL_KEY_SUFFIXES = [
  "authorization",
  "cookie",
  "cookieheader",
  "token",
  "secret",
  "credential",
  "apikey",
  "privatekey",
  "password",
  "passphrase",
  "clientsecret",
  "clientsecretvalue",
];

function normalizeSensitiveKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Return true when a field name conventionally carries credential material. */
export function isSensitiveCredentialKey(key: string): boolean {
  const normalized = normalizeSensitiveKey(key);
  return (
    SENSITIVE_CREDENTIAL_KEYS.has(normalized) ||
    SENSITIVE_CREDENTIAL_KEY_SUFFIXES.some((suffix) => normalized.endsWith(suffix))
  );
}

/**
 * Recursively inspect JSON-like input for credential-bearing field names.
 * Accessors, cycles, and excessive nesting fail closed without invoking code.
 */
export function containsSensitiveCredentialKey(
  value: unknown,
  depth = 0,
  ancestors = new Set<object>(),
): boolean {
  if (depth > 20) return true;
  if (!value || typeof value !== "object") return false;
  if (ancestors.has(value)) return true;

  ancestors.add(value);
  try {
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (!descriptor.enumerable) continue;
      if (isSensitiveCredentialKey(key) || !("value" in descriptor)) return true;
      if (containsSensitiveCredentialKey(descriptor.value, depth + 1, ancestors)) return true;
    }
    return false;
  } finally {
    ancestors.delete(value);
  }
}
