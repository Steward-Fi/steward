import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

test("agent state never fetches an operator-controlled price-oracle URL", () => {
  const source = readFileSync(join(import.meta.dir, "../state.ts"), "utf8");
  expect(source).not.toContain("PRICE_ORACLE_URL");
  expect(source).not.toContain("PRICE_ORACLE_");
  expect(source).not.toContain("fetch(url");
  expect(source).toContain("getHardenedOracleQuote(tokenAddress, chainId)");
});
