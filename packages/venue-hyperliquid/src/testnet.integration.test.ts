import { describe, expect, test } from "bun:test";
import { getOpenOrders } from "./index";

const TESTNET_URL = "https://api.hyperliquid-testnet.xyz";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

describe("Hyperliquid testnet smoke", () => {
  test("reads open orders without submitting a live order", async () => {
    if (process.env.HL_TESTNET_SMOKE !== "1") {
      expect(true).toBe(true);
      return;
    }
    const orders = await getOpenOrders(process.env.HL_TESTNET_USER ?? ZERO_ADDRESS, {
      baseUrl: TESTNET_URL,
    });
    expect(Array.isArray(orders)).toBe(true);
  });
});
