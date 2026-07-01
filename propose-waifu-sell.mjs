// Propose the agent-treasury $WAIFU wind-down sell (Option B) to the agent Safe.
// Builds 2 Safe txs (approve router + sell 100M via fee-on-transfer swap),
// signs each with Sol's key, and proposes to the Safe Transaction Service so
// Shadow can review + co-sign + execute in the Safe UI. NOTHING is broadcast
// here — Safe is 2-of-3, this only proposes Sol's signature.

import {
  createPublicClient,
  http,
  encodeFunctionData,
  parseUnits,
  encodeAbiParameters,
  keccak256,
  concat,
  getAddress,
} from "viem";
import { bsc } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import fs from "node:fs";

const RPC = process.env.BSC_RPC;
const SAFE = "0x440e903c5bb2c78de33d839613316d95ca2009e9";
const TOKEN = "0x15fc6086064afe50ccf4c70000c55cecb6e17777"; // WAIFU
const ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"; // PancakeV2
const WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c";
const TX_SERVICE = "https://api.safe.global/tx-service/bnb";

const AMOUNT = parseUnits("100000000", 18); // 100M WAIFU
const MIN_OUT_BNB = parseUnits("32", 18); // ~15% slippage floor on ~38 BNB
const DEADLINE = BigInt(Math.floor(Date.now() / 1000) + 1800); // 30 min

const key = JSON.parse(
  fs.readFileSync(process.env.HOME + "/.moltbot/secrets/sol-wallet.json", "utf8"),
);
const pk = (key.privateKey || key.key).startsWith("0x")
  ? key.privateKey || key.key
  : "0x" + (key.privateKey || key.key);
const account = privateKeyToAccount(pk);
console.log("Sol signer:", account.address);

const pub = createPublicClient({ chain: bsc, transport: http(RPC) });

const approveData = encodeFunctionData({
  abi: [
    {
      name: "approve",
      type: "function",
      inputs: [
        { name: "spender", type: "address" },
        { name: "amount", type: "uint256" },
      ],
      outputs: [{ type: "bool" }],
    },
  ],
  functionName: "approve",
  args: [ROUTER, AMOUNT],
});

const swapData = encodeFunctionData({
  abi: [
    {
      name: "swapExactTokensForETHSupportingFeeOnTransferTokens",
      type: "function",
      inputs: [
        { name: "amountIn", type: "uint256" },
        { name: "amountOutMin", type: "uint256" },
        { name: "path", type: "address[]" },
        { name: "to", type: "address" },
        { name: "deadline", type: "uint256" },
      ],
      outputs: [],
    },
  ],
  functionName: "swapExactTokensForETHSupportingFeeOnTransferTokens",
  args: [AMOUNT, MIN_OUT_BNB, [TOKEN, WBNB], SAFE, DEADLINE],
});

// EIP-712 SafeTx hashing (Safe v1.x)
const DOMAIN_TYPEHASH =
  "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"; // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
const SAFETX_TYPEHASH =
  "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8";

function safeTxHash({ to, value, data, operation, nonce }) {
  const dataHash = keccak256(data);
  const encoded = encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "address" },
      { type: "uint256" },
      { type: "bytes32" },
      { type: "uint8" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "address" },
      { type: "address" },
      { type: "uint256" },
    ],
    [
      SAFETX_TYPEHASH,
      to,
      value,
      dataHash,
      operation,
      0n,
      0n,
      0n,
      "0x0000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000",
      nonce,
    ],
  );
  const structHash = keccak256(encoded);
  const domainSeparator = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }],
      [DOMAIN_TYPEHASH, BigInt(bsc.id), SAFE],
    ),
  );
  return keccak256(concat(["0x1901", domainSeparator, structHash]));
}

async function proposeOne(label, to, data, nonce) {
  const tx = {
    to,
    value: 0n,
    data,
    operation: 0,
    nonce: BigInt(nonce),
  };
  const hash = safeTxHash(tx);
  console.log(`\n=== ${label} (nonce ${nonce}) ===`);
  console.log("  to:", to);
  console.log("  data:", data.slice(0, 30) + "...");
  console.log("  SafeTxHash:", hash);

  if (process.env.DRY_RUN === "1") {
    console.log("  [DRY RUN] not signing / not posting");
    return hash;
  }
  // sign the SafeTx hash (eth_sign style — Safe expects v adjusted +4 for eth_sign,
  // but EIP-712 signature with v 27/28 works for contract sig validation).
  const sig = await account.sign({ hash });
  console.log("  Sol signature:", sig);

  const body = {
    to: getAddress(to),
    value: "0",
    data,
    operation: 0,
    safeTxGas: "0",
    baseGas: "0",
    gasPrice: "0",
    gasToken: "0x0000000000000000000000000000000000000000",
    refundReceiver: "0x0000000000000000000000000000000000000000",
    nonce: String(nonce),
    contractTransactionHash: hash,
    sender: account.address,
    signature: sig,
    origin: "sol-waifu-winddown-B",
  };

  const res = await fetch(
    `${TX_SERVICE}/api/v1/safes/${getAddress(SAFE)}/multisig-transactions/`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  const text = await res.text();
  console.log(`  propose status: ${res.status} ${text.slice(0, 200)}`);
  return hash;
}

const startNonce = Number(process.env.SAFE_NONCE || "10");
console.log("Safe:", SAFE, "| start nonce:", startNonce);
console.log("Sell: 100,000,000 WAIFU -> BNB, minOut", MIN_OUT_BNB / 10n ** 18n, "BNB");

await proposeOne("APPROVE router 100M WAIFU", TOKEN, approveData, startNonce);
await proposeOne(
  "SELL 100M WAIFU -> BNB (fee-on-transfer)",
  ROUTER,
  swapData,
  startNonce + 1,
);
console.log("\nDONE. Review + co-sign in the Safe UI: https://app.safe.global");
