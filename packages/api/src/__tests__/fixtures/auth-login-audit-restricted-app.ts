import { closeDb } from "@stwd/db";
import { privateKeyToAccount } from "viem/accounts";

function buildSiweMessage(address: string, nonce: string): string {
  return [
    "steward.fi wants you to sign in with your Ethereum account:",
    address,
    "",
    "Sign in to Steward",
    "",
    "URI: https://steward.fi",
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}

const { authRoutes } = await import("../../routes/auth");
const privateKey = process.env.STEWARD_TEST_SIWE_PRIVATE_KEY;
if (!privateKey?.startsWith("0x")) throw new Error("STEWARD_TEST_SIWE_PRIVATE_KEY is required");
const account = privateKeyToAccount(privateKey as `0x${string}`);

try {
  const nonceResponse = await authRoutes.request("/nonce", {
    headers: { origin: "https://steward.fi" },
  });
  const nonceBody = (await nonceResponse.json()) as { nonce?: string; error?: string };
  if (nonceResponse.status !== 200 || !nonceBody.nonce) {
    throw new Error(`nonce failed (${nonceResponse.status}): ${nonceBody.error ?? "unknown"}`);
  }

  const message = buildSiweMessage(account.address, nonceBody.nonce);
  const signature = await account.signMessage({ message });
  const response = await authRoutes.request("/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://steward.fi",
      "x-request-id": "restricted-auth-login-audit-proof",
    },
    body: JSON.stringify({ message, signature }),
  });
  const responseText = await response.text();
  const body = JSON.parse(responseText) as {
    ok?: boolean;
    error?: string;
    userId?: string;
    tenant?: { id?: string };
  };
  if (response.status !== 200 || !body.userId || !body.tenant?.id) {
    throw new Error(`verify failed (${response.status}): ${body.error ?? responseText}`);
  }

  console.log(
    JSON.stringify({
      ok: true,
      status: response.status,
      tenantId: body.tenant.id,
      userId: body.userId,
      address: account.address.toLowerCase(),
    }),
  );
} finally {
  await closeDb();
}
