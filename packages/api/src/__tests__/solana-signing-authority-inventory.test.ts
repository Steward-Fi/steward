import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "vault.ts"), "utf8");
const rawVaultSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "vault", "src", "vault.ts"),
  "utf8",
);

function occurrences(source: string, needle: string): number[] {
  const indexes: number[] = [];
  let cursor = 0;
  while (true) {
    const index = source.indexOf(needle, cursor);
    if (index < 0) return indexes;
    indexes.push(index);
    cursor = index + needle.length;
  }
}

describe("raw Solana signer authority inventory", () => {
  it("has no boolean parsed-sign exemption anywhere in production", () => {
    expect(routeSource).not.toContain("allowParsedSign");
    expect(rawVaultSource).not.toContain("allowParsedSign");
  });

  it("pins all API raw serialized-transaction callers to blind or native-envelope modes", () => {
    const rawCalls = occurrences(routeSource, "vault.signSolanaTransaction({");
    expect(rawCalls).toHaveLength(3);
    const contexts = rawCalls.map((index) => routeSource.slice(index, index + 900));

    // Approval fallback: only a reviewed unsafe-blind row or the native envelope.
    expect(contexts[0]).toContain('queuedSolanaSigningMode === "blind"');
    expect(contexts[0]).toContain("allowBlindSign: true");
    expect(contexts[0]).toContain("expectedTo: transactionRow.toAddress");
    expect(contexts[0]).toContain("expectedValue: transactionRow.value");

    // Dedicated unsafe-blind helper still supplies a concrete policy envelope.
    expect(contexts[1]).toContain("expectedTo: toAddress");
    expect(contexts[1]).toContain("expectedValue: txValue");

    // Fully parsed direct signing reaches raw custody only for one native transfer.
    expect(routeSource.slice(rawCalls[2] - 250, rawCalls[2] + 700)).toContain(
      "isSingleNativeTransfer",
    );
    expect(contexts[2]).toContain("expectedTo: toAddress");
    expect(contexts[2]).toContain("expectedValue: txValue");
  });

  it("routes every parsed production family through the governed claim consumer", () => {
    expect(occurrences(routeSource, ".signSolanaParsedTransactionAuthorized(")).toHaveLength(3);
    expect(
      occurrences(routeSource, "consumeExecutionClaim: consumeParsedSolanaExecutionClaim"),
    ).toHaveLength(3);
    expect(routeSource).toContain("parsedExecutionClaimDigest");
    expect(routeSource).toContain("parsedClaimConsumedAt");
  });

  it("checks the opaque governed grant before querying encrypted Solana keys", () => {
    const method = rawVaultSource.indexOf("async signSolanaTransaction(");
    const grantCheck = rawVaultSource.indexOf(
      "assertGovernedParsedSolanaSigningGrant(request.governedParsedSign, request)",
      method,
    );
    const keyLookup = rawVaultSource.indexOf(".from(encryptedChainKeys)", grantCheck);
    expect(method).toBeGreaterThanOrEqual(0);
    expect(grantCheck).toBeGreaterThan(method);
    expect(keyLookup).toBeGreaterThan(grantCheck);
  });
});
