import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Source-introspection regression test for issue #103 (SIWS expiry / not-before).
//
// The Solana SIWS verify path historically ignored the signed message's own
// `Expiration Time` / `Not Before` fields, while the EVM SIWE path enforces
// both. This test asserts that:
//   1. parseSiwsMessage captures expirationTime / notBefore from the message.
//   2. POST /verify/solana rejects an expired or not-yet-valid message with the
//      same error strings/status the EVM path uses.
//   3. Those temporal checks run BEFORE the single-use nonce is consumed, so a
//      stale message cannot burn a fresh nonce.
//
// This mirrors the existing structural style of auth-nonce-binding.test.ts and
// fails on the pre-fix source (which has no expirationTime/notBefore handling).

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("SIWS temporal bounds (issue #103)", () => {
  it("parseSiwsMessage captures Expiration Time and Not Before fields", () => {
    const parseStart = authSource.indexOf("function parseSiwsMessage");
    expect(parseStart).toBeGreaterThanOrEqual(0);
    const parseEnd = authSource.indexOf("\nfunction verifySolanaMessageSignature", parseStart);
    const parseFn = authSource.slice(parseStart, parseEnd === -1 ? undefined : parseEnd);

    // Field keys are lowercased with whitespace stripped, so the map keys are
    // "expirationtime" and "notbefore".
    expect(parseFn).toContain('fields.get("expirationtime")');
    expect(parseFn).toContain('fields.get("notbefore")');
    expect(parseFn).toContain("expirationTime:");
    expect(parseFn).toContain("notBefore:");
  });

  it("ParsedSiwsMessage type carries expirationTime and notBefore", () => {
    const typeStart = authSource.indexOf("type ParsedSiwsMessage = {");
    expect(typeStart).toBeGreaterThanOrEqual(0);
    const typeEnd = authSource.indexOf("};", typeStart);
    const typeBlock = authSource.slice(typeStart, typeEnd);
    expect(typeBlock).toContain("expirationTime?: string");
    expect(typeBlock).toContain("notBefore?: string");
  });

  it("/verify/solana enforces expiry and not-before with the EVM error shapes", () => {
    const siwsStart = authSource.indexOf('auth.post("/verify/solana"');
    expect(siwsStart).toBeGreaterThanOrEqual(0);
    const siwsEnd = authSource.indexOf('auth.post("', siwsStart + 1);
    const route = authSource.slice(siwsStart, siwsEnd === -1 ? undefined : siwsEnd);

    expect(route).toContain("parsed.expirationTime");
    expect(route).toContain("parsed.notBefore");
    // Same error strings as the EVM /verify/ethereum path.
    expect(route).toContain('error: "Invalid expirationTime"');
    expect(route).toContain('error: "Message expired"');
    expect(route).toContain('error: "Invalid notBefore"');
    expect(route).toContain('error: "Message not yet valid"');
  });

  it("rejects expired/not-yet-valid messages BEFORE consuming the nonce", () => {
    const siwsStart = authSource.indexOf('auth.post("/verify/solana"');
    expect(siwsStart).toBeGreaterThanOrEqual(0);
    const siwsEnd = authSource.indexOf('auth.post("', siwsStart + 1);
    const route = authSource.slice(siwsStart, siwsEnd === -1 ? undefined : siwsEnd);

    const expCheck = route.indexOf("parsed.expirationTime");
    const nbCheck = route.indexOf("parsed.notBefore");
    const nonceConsume = route.indexOf("consumeSiweNonce(parsed.nonce)");
    const signatureCheck = route.indexOf("verifySolanaMessageSignature");

    expect(expCheck).toBeGreaterThanOrEqual(0);
    expect(nbCheck).toBeGreaterThan(expCheck);
    expect(nonceConsume).toBeGreaterThan(nbCheck);
    // Preserve the existing invariant: nonce is consumed before signature check.
    expect(signatureCheck).toBeGreaterThan(nonceConsume);
  });
});
