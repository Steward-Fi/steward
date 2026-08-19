import { validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

export const WALLET_E2E_CREDENTIAL_NAMES = [
  "E2E_METAMASK_SEED_PHRASE",
  "E2E_METAMASK_PASSWORD",
  "E2E_PHANTOM_SEED_PHRASE",
  "E2E_PHANTOM_PASSWORD",
] as const;

type CredentialName = (typeof WALLET_E2E_CREDENTIAL_NAMES)[number];
type CredentialEnvironment = Readonly<Record<string, string | undefined>>;

export interface WalletE2ECredentials {
  metamaskSeedPhrase: string;
  metamaskPassword: string;
  phantomSeedPhrase: string;
  phantomPassword: string;
}

function requiredValue(env: CredentialEnvironment, name: CredentialName): string {
  return env[name]?.trim() ?? "";
}

function assertSeedPhrase(name: CredentialName, value: string): void {
  const wordCount = value.split(/\s+/u).length;
  if (![12, 15, 18, 21, 24].includes(wordCount)) {
    throw new Error(
      `${name} must contain a complete BIP-39 word count (12, 15, 18, 21, or 24 words)`,
    );
  }
  if (!validateMnemonic(value, wordlist)) {
    throw new Error(`${name} must contain a valid BIP-39 mnemonic`);
  }
}

function assertPassword(name: CredentialName, value: string): void {
  if (value.length < 12) {
    throw new Error(`${name} must contain at least 12 characters`);
  }
}

/**
 * Fail-closed preflight for the opt-in wallet suite. Error text names missing
 * variables but never includes credential values.
 */
export function readWalletE2ECredentials(
  env: CredentialEnvironment = process.env,
): WalletE2ECredentials {
  const missing = WALLET_E2E_CREDENTIAL_NAMES.filter(
    (name) => requiredValue(env, name).length === 0,
  );
  if (missing.length > 0) {
    throw new Error(
      `Wallet E2E credentials are not provisioned. Missing: ${missing.join(", ")}. Use dedicated empty test wallets; never use live or funded wallet material.`,
    );
  }

  const credentials = {
    metamaskSeedPhrase: requiredValue(env, "E2E_METAMASK_SEED_PHRASE"),
    metamaskPassword: requiredValue(env, "E2E_METAMASK_PASSWORD"),
    phantomSeedPhrase: requiredValue(env, "E2E_PHANTOM_SEED_PHRASE"),
    phantomPassword: requiredValue(env, "E2E_PHANTOM_PASSWORD"),
  };
  assertSeedPhrase("E2E_METAMASK_SEED_PHRASE", credentials.metamaskSeedPhrase);
  assertPassword("E2E_METAMASK_PASSWORD", credentials.metamaskPassword);
  assertSeedPhrase("E2E_PHANTOM_SEED_PHRASE", credentials.phantomSeedPhrase);
  assertPassword("E2E_PHANTOM_PASSWORD", credentials.phantomPassword);
  return credentials;
}

export function assertWalletE2ECredentials(env: CredentialEnvironment = process.env): void {
  readWalletE2ECredentials(env);
}

/**
 * Wallet material is needed by the Playwright process, but never by the API,
 * web, or fake-provider services that the harness starts.
 */
export function environmentWithoutWalletCredentials(
  env: CredentialEnvironment = process.env,
): NodeJS.ProcessEnv {
  const sanitized: Record<string, string | undefined> = { ...env };
  for (const name of WALLET_E2E_CREDENTIAL_NAMES) delete sanitized[name];
  return sanitized as NodeJS.ProcessEnv;
}

/** Keep wallet values in the already-loaded setup closures, not browser children. */
export async function withWalletCredentialsRemoved<T>(callback: () => Promise<T>): Promise<T> {
  const saved = new Map<CredentialName, string | undefined>();
  for (const name of WALLET_E2E_CREDENTIAL_NAMES) {
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
  try {
    return await callback();
  } finally {
    for (const name of WALLET_E2E_CREDENTIAL_NAMES) {
      const value = saved.get(name);
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
