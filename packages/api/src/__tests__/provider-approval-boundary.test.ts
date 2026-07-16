/**
 * PR3 static boundary test (I15 / spec §14 static import guard). Proves the
 * provider-approval service source has ZERO references to credential decryption,
 * the proxy, nonce claims, network I/O, or the legacy PR #181
 * pending_proxy_requests fallback. PR4 deliberately composes one narrow mint-only
 * service into resume so execution_ready and its v2 authorization commit in the
 * same audited transaction. This source-introspection test permits exactly that
 * PR4 mint seam while continuing to reject any other execution-authorization
 * implementation or claim/dispatch behavior in the PR3 transition owner.
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

describe("PR3 boundary (I15): no decrypt / proxy / mint / nonce / network in the transition owner", () => {
  const forbidden: Array<[string, RegExp]> = [
    ["credential decryption", /decrypt|getSecretPlaintext|decryptSecret/i],
    ["proxy dispatch", /\bproxy\b|forwardRequest|dispatchProxy|handleProxy/i],
    [
      "execution-authorization implementation other than the PR4 mint seam",
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

  test("imports only DB + shared + drizzle plus the narrow PR4 mint seam", () => {
    // Guard the forbidden package specifiers anywhere in the source.
    expect(svc).not.toMatch(
      /from "@stwd\/proxy|from "@stwd\/vault|from "@stwd\/secrets|proxy-client/,
    );
    // The transition owner pulls from @stwd/db + @stwd/shared + drizzle-orm,
    // plus exactly one local mint-only service owned by PR4.
    expect(svc).toMatch(/from "@stwd\/db"/);
    expect(svc).toMatch(/from "@stwd\/shared"/);
    expect(svc.match(/from "\.\/provider-execution\.js"/g)).toHaveLength(1);
    expect(svc.match(/mintProviderExecutionAuthorizationWithinTx/g)).toHaveLength(7);
  });
});
