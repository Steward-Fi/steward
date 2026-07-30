/**
 * `steward secrets` — operator CLI for the sealed SecretStore (age-file backend).
 *
 * This is the sovereign-custody onboarding surface described in
 * DSTACK-CANONICAL §4B: a secret is encrypted DIRECTLY to the store's public
 * recipient on the operator's own machine and only the CIPHERTEXT is written to
 * the store. The plaintext is read from stdin or a file — never from a flag or
 * an env var — so it does not land in shell history or the process environment
 * where avoidable.
 *
 * Commands:
 *   steward secrets init   [--store DIR]
 *       Generate an age identity/recipient pair. Writes ONLY recipient.txt to
 *       the store. Prints the private identity ONCE to stdout — the operator
 *       must seal it themselves (TEE KMS, hardware token, offline backup).
 *   steward secrets recipient [--store DIR]
 *       Print the store's public recipient (for scripting `age -r`).
 *   steward secrets put <path> [--store DIR] [--file F | (stdin)] [--desc TEXT] [--overwrite]
 *       Read plaintext from --file or stdin, encrypt to the recipient, store it.
 *   steward secrets rotate <path> [--store DIR] [--file F | (stdin)]
 *       Replace an existing secret, bumping its version.
 *   steward secrets list   [--store DIR]
 *       List metadata (path/version/timestamps). NEVER prints values.
 *   steward secrets rm <path> [--store DIR]
 *       Delete a secret.
 *
 * There is NO `steward secrets get`. That omission is the security property:
 * the store is write + exercise only. Secrets are exercised by the running
 * Steward process (broker/inject/sign), never handed back to an operator.
 */

import { readFileSync } from "node:fs";
import { AgeFileSecretStore, sealToRecipient } from "@stwd/vault";
import { boolFlag, required, stringFlag } from "./args";

const DEFAULT_STORE_DIR = process.env.STEWARD_SECRET_STORE_DIR ?? ".steward/secret-store";

function storeDir(flags: Record<string, string | boolean>): string {
  return stringFlag(flags, "store") ?? DEFAULT_STORE_DIR;
}

/** Read the plaintext to onboard: --file <path>, or stdin. Never from a flag. */
function readPlaintext(flags: Record<string, string | boolean>): string {
  const file = stringFlag(flags, "file");
  if (file) {
    // Strip a single trailing newline (editors add one) but keep interior bytes.
    return readFileSync(file, "utf8").replace(/\n$/, "");
  }
  if (stringFlag(flags, "value") !== undefined) {
    throw new Error(
      "refusing --value: secrets must come from --file or stdin, not a flag (shell history leak). " +
        'Pipe it: printf %s "$SECRET" | steward secrets put <path>',
    );
  }
  // Read all of stdin.
  const data = readFileSync(0, "utf8");
  const trimmed = data.replace(/\n$/, "");
  if (!trimmed) {
    throw new Error(
      "no plaintext on stdin. Provide --file <path> or pipe the secret in: " +
        'printf %s "$SECRET" | steward secrets put <path>',
    );
  }
  return trimmed;
}

export async function secretsStoreCommand(
  action: string | undefined,
  flags: Record<string, string | boolean>,
): Promise<unknown> {
  const dir = storeDir(flags);

  if (action === "init") {
    const { recipient, identity } = await AgeFileSecretStore.initStore(dir);
    return {
      store: dir,
      recipient,
      identity,
      warning:
        "This is the ONLY time the private identity is shown. Seal it now (TEE KMS / hardware token / offline backup). " +
        "The store persists ONLY the recipient; losing the identity means secrets are unrecoverable (by design).",
    };
  }

  if (action === "recipient") {
    const store = new AgeFileSecretStore({ storeDir: dir });
    return { store: dir, recipient: await store.recipient() };
  }

  if (action === "put") {
    const path = required(positional(flags), "path");
    const store = new AgeFileSecretStore({ storeDir: dir });
    const recipient = await store.recipient();
    const plaintext = readPlaintext(flags);
    const sealed = await sealToRecipient(recipient, plaintext);
    const meta = await store.putSealed(path, sealed, {
      description: stringFlag(flags, "desc"),
      overwrite: boolFlag(flags, "overwrite"),
    });
    return { onboarded: meta.path, version: meta.version, sealedTo: recipient };
  }

  if (action === "rotate") {
    const path = required(positional(flags), "path");
    const store = new AgeFileSecretStore({ storeDir: dir });
    const recipient = await store.recipient();
    const sealed = await sealToRecipient(recipient, readPlaintext(flags));
    const meta = await store.rotateSealed(path, sealed);
    return { rotated: meta.path, version: meta.version };
  }

  if (action === "list") {
    const store = new AgeFileSecretStore({ storeDir: dir });
    return { store: dir, secrets: await store.list() };
  }

  if (action === "rm") {
    const path = required(positional(flags), "path");
    const store = new AgeFileSecretStore({ storeDir: dir });
    return { deleted: await store.delete(path), path };
  }

  throw new Error(
    "Supported secrets commands: secrets init|recipient|put|rotate|list|rm. " +
      "There is no 'get' — the store is write + exercise only.",
  );
}

/**
 * The <path> positional. The top-level dispatcher parses [command, action]
 * from positionals; the secret path is the THIRD positional. We stash the raw
 * positionals on a well-known flag key so this module stays decoupled from the
 * main arg parser's shape.
 */
function positional(flags: Record<string, string | boolean>): string | undefined {
  const raw = flags.__path;
  return typeof raw === "string" ? raw : undefined;
}
