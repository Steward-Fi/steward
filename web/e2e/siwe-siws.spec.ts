import { expect, test } from "@playwright/test";
import {
  buildSiweMessage,
  buildSiwsMessage,
  makeEvmSigner,
  makeSolanaSigner,
} from "./fixtures/wallet-signing";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";
const DOMAIN = new URL(WEB).host;

/**
 * The server binds each SIWE nonce to an allowed Origin (and rejects nonce
 * requests that carry none). A real browser attaches that Origin header
 * automatically to the cross-origin fetch the SDK makes; Playwright's
 * APIRequestContext does not, so we send it explicitly to exercise the genuine
 * origin-bound nonce path rather than the unauthenticated rejection.
 */
function fetchNonce(request: import("@playwright/test").APIRequestContext) {
  return request.get(`${API}/auth/nonce`, { headers: { Origin: WEB } });
}

test.describe("SIWE / SIWS — legitimate signatures against live API", () => {
  test("SIWE: fresh EVM keypair signs and verifies, mints JWT", async ({ request }) => {
    const nonceRes = await fetchNonce(request);
    expect(nonceRes.ok()).toBe(true);
    const { nonce } = (await nonceRes.json()) as { nonce: string };
    expect(nonce.length).toBeGreaterThan(8);

    const signer = await makeEvmSigner();
    const message = buildSiweMessage({
      domain: DOMAIN,
      address: signer.address,
      uri: WEB,
      nonce,
      chainId: 1,
    });
    const signature = await signer.sign(message);

    const verifyRes = await request.post(`${API}/auth/verify`, {
      data: { message, signature },
    });
    expect(verifyRes.status()).toBe(200);
    const body = (await verifyRes.json()) as {
      ok: boolean;
      token: string;
      refreshToken: string;
      address: string;
    };
    expect(body.ok).toBe(true);
    expect(body.address.toLowerCase()).toBe(signer.address.toLowerCase());
    expect(body.token.split(".").length).toBe(3);
  });

  test("SIWE: nonce is single-use", async ({ request }) => {
    const { nonce } = (await (await fetchNonce(request)).json()) as { nonce: string };
    const signer = await makeEvmSigner();
    const message = buildSiweMessage({
      domain: DOMAIN,
      address: signer.address,
      uri: WEB,
      nonce,
    });
    const signature = await signer.sign(message);

    const first = await request.post(`${API}/auth/verify`, { data: { message, signature } });
    expect(first.status()).toBe(200);

    const second = await request.post(`${API}/auth/verify`, { data: { message, signature } });
    expect(second.status()).toBe(401);
  });

  test("SIWS: fresh Solana keypair signs and verifies, mints JWT", async ({ request }) => {
    const { nonce } = (await (await fetchNonce(request)).json()) as { nonce: string };
    const signer = makeSolanaSigner();
    const message = buildSiwsMessage({
      domain: DOMAIN,
      publicKey: signer.address,
      uri: WEB,
      nonce,
      chainId: "mainnet",
    });
    const signature = signer.sign(message);

    const verifyRes = await request.post(`${API}/auth/verify/solana`, {
      data: { message, signature, publicKey: signer.address },
    });
    expect(verifyRes.status()).toBe(200);
    const body = (await verifyRes.json()) as { ok: boolean; address: string; token: string };
    expect(body.ok).toBe(true);
    expect(body.address).toBe(signer.address);
    expect(body.token.split(".").length).toBe(3);
  });

  test("SIWS: rejects a tampered signature", async ({ request }) => {
    const { nonce } = (await (await fetchNonce(request)).json()) as { nonce: string };
    const signer = makeSolanaSigner();
    const message = buildSiwsMessage({
      domain: DOMAIN,
      publicKey: signer.address,
      uri: WEB,
      nonce,
    });
    // Sign a different message; the server should reject signature/message mismatch.
    const badSig = signer.sign(`${message}\nTampered: true`);

    const res = await request.post(`${API}/auth/verify/solana`, {
      data: { message, signature: badSig, publicKey: signer.address },
    });
    expect(res.status()).toBe(401);
  });
});
