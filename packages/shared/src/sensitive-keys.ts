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
  "accesskeyid",
  "accesskey",
  "secretaccesskey",
  "secretkey",
  "sessionid",
  "sessioncookie",
  "clientcertificate",
  "clientcert",
  "signingkey",
  "encryptionkey",
  "mnemonic",
  "seedphrase",
  "recoveryphrase",
  "jwt",
  "pat",
  "bearer",
]);

const SENSITIVE_CREDENTIAL_KEY_SUFFIXES = [
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
  "accesskeyid",
  "accesskey",
  "secretaccesskey",
  "secretkey",
  "sessionid",
  "sessioncookie",
  "clientcertificate",
  "clientcert",
  "signingkey",
  "encryptionkey",
  "mnemonic",
  "seedphrase",
  "recoveryphrase",
  "jwt",
];

const SENSITIVE_CREDENTIAL_KEY_DECORATORS = ["header", "value"];

function normalizeSensitiveKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Return true when a field name conventionally carries credential material. */
export function isSensitiveCredentialKey(key: string): boolean {
  const normalized = normalizeSensitiveKey(key);
  // Carrier decorators are commonly stacked or pluralized, for example
  // `authorizationHeaderValue`, `credential_headers`, and `apiKeys`. Peel them
  // to a fixed point instead of removing only one layer, which would leave
  // nested carrier names undetected.
  const pending = [normalized];
  const candidates = new Set<string>();
  while (pending.length > 0) {
    const candidate = pending.pop()!;
    if (!candidate || candidates.has(candidate)) continue;
    candidates.add(candidate);
    if (candidate.endsWith("s") && candidate.length > 1) {
      pending.push(candidate.slice(0, -1));
    }
    for (const decorator of SENSITIVE_CREDENTIAL_KEY_DECORATORS) {
      if (candidate.endsWith(decorator) && candidate.length > decorator.length) {
        pending.push(candidate.slice(0, -decorator.length));
      }
    }
  }
  return [...candidates].some(
    (candidate) =>
      SENSITIVE_CREDENTIAL_KEYS.has(candidate) ||
      SENSITIVE_CREDENTIAL_KEY_SUFFIXES.some((suffix) => candidate.endsWith(suffix)),
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
