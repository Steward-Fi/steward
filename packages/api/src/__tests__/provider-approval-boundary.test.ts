/**
 * Static authority-boundary inventory. The provider-approval transition owner
 * must not decrypt credentials, dispatch network requests, or claim execution
 * nonces. It may call the dedicated authorization minter so execution readiness
 * and its authorization commit share one audited transaction.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const raw = readFileSync(join(import.meta.dir, "..", "services", "provider-approval.ts"), "utf8");

// Strip line + block comments so the guard matches CODE, not prose describing
// the boundary (the file legitimately DOCUMENTS that it never decrypts/proxies).
const svc = raw
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("\n")
  .map((l) => l.replace(/\/\/.*$/, ""))
  .join("\n");

describe("approval-lifecycle boundary (I15): no decrypt / proxy / mint / nonce / network in the transition owner", () => {
  const forbidden: Array<[string, RegExp]> = [
    ["credential decryption", /decrypt|getSecretPlaintext|decryptSecret/i],
    ["proxy dispatch", /\bproxy\b|forwardRequest|dispatchProxy|handleProxy/i],
    [
      "execution-authorization implementation other than the governed-execution mint seam",
      /mintExecutionAuthorization|execution-authorization|executionAuthorization(?!WithinTx)/i,
    ],
    ["nonce claim", /executionAuthorizationNonces|claimNonce|nonceClaim/i],
    ["network I/O", /\bfetch\(|axios|node:https?|undici/],
    ["legacy pending_proxy_requests fallback", /pendingProxyRequests|pending_proxy_requests/],
  ];

  for (const [label, re] of forbidden) {
    test(`does not reference ${label}`, () => {
      expect(re.test(svc)).toBe(false);
    });
  }

  test("imports only DB + shared + drizzle plus the narrow governed-execution mint seam", () => {
    // Guard the forbidden package specifiers anywhere in the source.
    expect(svc).not.toMatch(
      /from "@stwd\/proxy|from "@stwd\/vault|from "@stwd\/secrets|proxy-client/,
    );
    // The transition owner pulls from @stwd/db + @stwd/shared + drizzle-orm,
    // plus exactly one local mint-only service owned by governed-execution.
    expect(svc).toMatch(/from "@stwd\/db"/);
    expect(svc).toMatch(/from "@stwd\/shared"/);
    expect(svc.match(/from "\.\/provider-execution\.js"/g)).toHaveLength(1);
    expect(svc.match(/mintProviderExecutionAuthorizationWithinTx/g)).toHaveLength(7);
  });
});
