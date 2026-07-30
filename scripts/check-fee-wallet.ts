#!/usr/bin/env bun
/**
 * check-fee-wallet.ts — READ-ONLY audit of the waifu.fun platform fee wallet.
 *
 * Companion to docs/runbooks/SAFE-ROTATION.md (Safe 2-of-3 rotation runbook).
 *
 * Reports, for the fee wallet (and optionally any --address):
 *   - BNB balance + nonce
 *   - whether it is a contract; if it is a Safe: version, owners, threshold
 *   - whether env config (WAIFU_PLATFORM_FEE_WALLET / PLATFORM_COMMISSION_RECEIVER /
 *     PLATFORM_RECEIVER) matches EXPECTED_FEE_WALLET
 *   - recent incoming transactions (only when BSCSCAN_API_KEY is provided)
 *
 * HARD GUARANTEES: no private keys, no signing, no state-changing RPC methods.
 * The only JSON-RPC methods used are eth_getBalance, eth_getTransactionCount,
 * eth_getCode, eth_getStorageAt, and eth_call.
 *
 * Usage:
 *   bun run scripts/check-fee-wallet.ts
 *   bun run scripts/check-fee-wallet.ts --address 0x...
 *   EXPECTED_FEE_WALLET=0x... WAIFU_PLATFORM_FEE_WALLET=0x... bun run scripts/check-fee-wallet.ts
 *   BSCSCAN_API_KEY=... bun run scripts/check-fee-wallet.ts
 */

const RPC_URL = process.env.BSC_RPC_URL ?? "https://bsc-dataseed.binance.org/";

/** waifu.fun platform fee wallet (single-key burner being rotated away from). */
const FEE_WALLET = "0xC9846a839c4e1D9050Dc890A25661AB13224e9EC";
/** Existing platform Safe (LaunchFactory platformCommissionReceiver on BSC mainnet). */
const PLATFORM_SAFE = "0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c";

/** Known Safe singleton addresses on BSC (safe-global/safe-deployments, canonical). */
const KNOWN_SINGLETONS: Record<string, string> = {
  "0x29fcb43b46531bca003ddc8fcb67ffe91900c762": "SafeL2 v1.4.1",
  "0x3e5c63644e683549055b9be8653de26e0b4cd36e": "SafeL2 v1.3.0",
  "0xedd160febbd92e350d4d398fb636302fccd67c7e": "SafeL2 v1.5.0",
};

let rpcId = 0;
async function rpc(method: string, params: unknown[]): Promise<string> {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
  });
  if (!res.ok) throw new Error(`RPC HTTP ${res.status} for ${method}`);
  const body = (await res.json()) as { result?: string; error?: { message: string } };
  if (body.error) throw new Error(`RPC error for ${method}: ${body.error.message}`);
  if (body.result === undefined) throw new Error(`RPC empty result for ${method}`);
  return body.result;
}

const isAddress = (v: string | undefined): v is string =>
  typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
const norm = (a: string) => a.toLowerCase();
const bnb = (hexWei: string) => (Number(BigInt(hexWei)) / 1e18).toFixed(6);

/** Decode an ABI-encoded address[] return (offset + length + words). */
function decodeAddressArray(hex: string): string[] {
  const data = hex.replace(/^0x/, "");
  if (data.length < 128) return [];
  const len = Number(BigInt(`0x${data.slice(64, 128)}`));
  const out: string[] = [];
  for (let i = 0; i < len; i++) {
    const word = data.slice(128 + i * 64, 128 + (i + 1) * 64);
    out.push(`0x${word.slice(24)}`);
  }
  return out;
}

/** Decode an ABI-encoded string return. */
function decodeString(hex: string): string {
  const data = hex.replace(/^0x/, "");
  if (data.length < 128) return "";
  const len = Number(BigInt(`0x${data.slice(64, 128)}`));
  const bytes = data.slice(128, 128 + len * 2);
  return Buffer.from(bytes, "hex").toString("utf8");
}

interface SafeInfo {
  singleton: string;
  singletonLabel: string;
  version: string;
  owners: string[];
  threshold: number;
}

async function inspectSafe(address: string): Promise<SafeInfo | null> {
  try {
    const slot0 = await rpc("eth_getStorageAt", [address, "0x0", "latest"]);
    const singleton = `0x${slot0.slice(-40)}`;
    if (singleton === `0x${"0".repeat(40)}`) return null;
    const [ownersRaw, thresholdRaw, versionRaw] = await Promise.all([
      rpc("eth_call", [{ to: address, data: "0xa0e67e2b" }, "latest"]), // getOwners()
      rpc("eth_call", [{ to: address, data: "0xe75235b8" }, "latest"]), // getThreshold()
      rpc("eth_call", [{ to: address, data: "0xffa1ad74" }, "latest"]), // VERSION()
    ]);
    return {
      singleton,
      singletonLabel: KNOWN_SINGLETONS[norm(singleton)] ?? "UNKNOWN singleton (verify!)",
      version: decodeString(versionRaw),
      owners: decodeAddressArray(ownersRaw),
      threshold: Number(BigInt(thresholdRaw)),
    };
  } catch {
    return null; // not a Safe (or proxy with a different layout)
  }
}

async function auditAddress(label: string, address: string): Promise<void> {
  const [balance, nonce, code] = await Promise.all([
    rpc("eth_getBalance", [address, "latest"]),
    rpc("eth_getTransactionCount", [address, "latest"]),
    rpc("eth_getCode", [address, "latest"]),
  ]);
  const isContract = code !== "0x";
  console.log(`\n== ${label}: ${address}`);
  console.log(`   type:      ${isContract ? "contract" : "EOA"}`);
  console.log(`   balance:   ${bnb(balance)} BNB`);
  console.log(`   nonce:     ${Number(BigInt(nonce))}`);
  if (isContract) {
    const safe = await inspectSafe(address);
    if (safe) {
      console.log(
        `   safe:      version=${safe.version} threshold=${safe.threshold}-of-${safe.owners.length}`,
      );
      console.log(`   singleton: ${safe.singleton} (${safe.singletonLabel})`);
      for (const owner of safe.owners) console.log(`   owner:     ${owner}`);
    } else {
      console.log("   safe:      not detected (contract, but no Safe-shaped storage/ABI)");
    }
  }
}

async function recentInflows(address: string, apiKey: string): Promise<void> {
  const url =
    `https://api.etherscan.io/v2/api?chainid=56&module=account&action=txlist` +
    `&address=${address}&page=1&offset=10&sort=desc&apikey=${apiKey}`;
  const res = await fetch(url);
  const body = (await res.json()) as {
    status: string;
    result:
      | Array<{ from: string; to: string; value: string; timeStamp: string; hash: string }>
      | string;
  };
  if (body.status !== "1" || !Array.isArray(body.result)) {
    console.log(
      `   inflows:   unavailable (${typeof body.result === "string" ? body.result : "api error"})`,
    );
    return;
  }
  const inbound = body.result.filter((tx) => norm(tx.to) === norm(address) && tx.value !== "0");
  console.log(`   recent inbound txs (of last 10 total):`);
  for (const tx of inbound) {
    const when = new Date(Number(tx.timeStamp) * 1000).toISOString();
    console.log(
      `     ${when}  ${(Number(BigInt(tx.value)) / 1e18).toFixed(6)} BNB  from ${tx.from}  ${tx.hash}`,
    );
  }
  if (inbound.length === 0) console.log("     (none in the last 10 transactions)");
}

function checkEnvMatch(): void {
  const expected = process.env.EXPECTED_FEE_WALLET;
  if (!isAddress(expected)) {
    console.log("\n== env check: skipped (set EXPECTED_FEE_WALLET=0x... to enable)");
    return;
  }
  console.log(`\n== env check (expected fee wallet: ${expected})`);
  let failures = 0;
  for (const key of [
    "WAIFU_PLATFORM_FEE_WALLET",
    "PLATFORM_COMMISSION_RECEIVER",
    "PLATFORM_RECEIVER",
  ]) {
    const value = process.env[key];
    if (value === undefined) {
      console.log(`   ${key}: (unset)`);
      continue;
    }
    const ok = isAddress(value) && norm(value) === norm(expected);
    if (!ok) failures++;
    console.log(`   ${key}: ${value} ${ok ? "MATCH" : "MISMATCH"}`);
  }
  if (failures > 0) {
    console.log(`   RESULT: ${failures} mismatch(es)`);
    process.exitCode = 1;
  } else {
    console.log("   RESULT: all set vars match");
  }
}

async function main(): Promise<void> {
  const argIdx = process.argv.indexOf("--address");
  const custom = argIdx !== -1 ? process.argv[argIdx + 1] : undefined;
  if (argIdx !== -1 && !isAddress(custom)) {
    console.error("--address requires a valid 0x address");
    process.exit(2);
  }

  console.log(`fee-wallet audit — rpc: ${RPC_URL} — ${new Date().toISOString()}`);

  if (custom) {
    await auditAddress("custom", custom);
  } else {
    await auditAddress("fee wallet (burner)", FEE_WALLET);
    await auditAddress("platform safe", PLATFORM_SAFE);
  }

  const apiKey = process.env.BSCSCAN_API_KEY ?? process.env.ETHERSCAN_API_KEY;
  if (apiKey) await recentInflows(custom ?? FEE_WALLET, apiKey);
  else console.log("\n== inflows: skipped (set BSCSCAN_API_KEY or ETHERSCAN_API_KEY to enable)");

  checkEnvMatch();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
});
