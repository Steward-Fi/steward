/**
 * PR3 static boundary test (I15 / spec §14 static import guard). Proves the
 * provider-approval service source has ZERO references to credential decryption,
 * the proxy, execution-authorization minting, nonce claims, network I/O, or the
 * legacy PR #181 pending_proxy_requests fallback. This is a source-introspection
 * test: a future edit that pulls any of those into the PR3 transition owner
 * fails CI, not a runtime spy.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const raw = readFileSync(
  join(import.meta.dir, "..", "services", "provider-approval.ts"),
  "utf8",
);

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
    ["execution-authorization mint", /mintExecutionAuthorization|execution-authorization|executionAuthorization/i],
    ["nonce claim", /executionAuthorizationNonces|claimNonce|nonceClaim/i],
    ["network I/O", /\bfetch\(|axios|node:https?|undici/],
    ["legacy pending_proxy_requests fallback", /pendingProxyRequests|pending_proxy_requests/],
  ];

  for (const [label, re] of forbidden) {
    test(`does not reference ${label}`, () => {
      expect(re.test(svc)).toBe(false);
    });
  }

  test("imports only DB + shared + drizzle (no vault/proxy/secret packages)", () => {
    // Guard the forbidden package specifiers anywhere in the source.
    expect(svc).not.toMatch(/from "@stwd\/proxy|from "@stwd\/vault|from "@stwd\/secrets|proxy-client/);
    // The transition owner pulls from @stwd/db + @stwd/shared + drizzle-orm.
    expect(svc).toMatch(/from "@stwd\/db"/);
    expect(svc).toMatch(/from "@stwd\/shared"/);
  });
});
