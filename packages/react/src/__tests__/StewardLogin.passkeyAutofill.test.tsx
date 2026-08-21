/**
 * Passkey conditional-mediation (autofill) regression coverage.
 *
 * Bug (2026-08-20): the email input carried `autoComplete="email webauthn"`.
 * The `webauthn` autofill token arms browser conditional mediation, which
 * surfaces ANY discoverable passkey stored for the relying party the moment
 * the field is focused — ignoring the email being typed. A user composing a
 * BRAND-NEW email was prompted with an EXISTING account's passkey, blocking
 * new-account signup.
 *
 * Invariant locked in here: typing a new email must never surface an
 * existing account's passkey. Passkey login remains available via the
 * explicit passkey button, which scopes to the typed email through
 * `signInWithPasskey(email)` → `/auth/passkey/login/options`.
 *
 * jsdom/happy-dom cannot exercise real WebAuthn conditional UI, so we assert
 * at the levels we control deterministically:
 *   1. The email input's `autocomplete` attribute is exactly "email"
 *      (no `webauthn` token → browser never arms conditional mediation).
 *   2. No `navigator.credentials.get()` call is issued on mount or while
 *      typing (no programmatic conditional mediation either).
 *   3. The explicit passkey button still initiates email-scoped passkey
 *      login with the typed email.
 */

import { beforeAll, describe, expect, test } from "bun:test";

interface MountedPasskeyProbe {
  autocomplete: string | null;
  credentialsCallsAfterMount: number;
  credentialsCallsAfterTyping: number;
  passkeyCallsAfterTyping: string[];
  passkeyCallsAfterClick: string[];
}

let probe: MountedPasskeyProbe;

beforeAll(async () => {
  // The mounted probe needs happy-dom and react-dom/client. Run it in a child
  // process so those browser globals and module-cache choices cannot mutate
  // the rest of the package's SSR-oriented test process.
  const fixture = new URL("./fixtures/passkey-autofill-mounted.tsx", import.meta.url).pathname;
  const child = Bun.spawn(["bun", fixture], {
    cwd: new URL("../..", import.meta.url).pathname,
    stdout: "pipe",
    stderr: "pipe",
    env: process.env,
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (code !== 0) {
    throw new Error(`mounted passkey probe failed (${code}):\n${stderr || stdout}`);
  }
  probe = JSON.parse(stdout.trim()) as MountedPasskeyProbe;
});

describe("passkey conditional-mediation autofill regression", () => {
  test("email input does not carry the webauthn autofill token", () => {
    expect(probe.autocomplete).toBe("email");
    expect(probe.autocomplete).not.toContain("webauthn");
  });

  test("no conditional-mediation credentials.get() on mount or while typing a new email", () => {
    expect(probe.credentialsCallsAfterMount).toBe(0);
    expect(probe.credentialsCallsAfterTyping).toBe(0);
    expect(probe.passkeyCallsAfterTyping).toEqual([]);
  });

  test("explicit passkey button still initiates email-scoped passkey login", () => {
    expect(probe.passkeyCallsAfterClick).toEqual(["brand-new-user@example.com"]);
  });
});
