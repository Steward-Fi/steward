# @stwd/proxy-client

Agent-side client for the Steward proxy.

The proxy holds the upstream API credentials. Agents never see them: they send
requests to the proxy with a scoped JWT and (in production) an HMAC
proof-of-possession signature. The proxy authenticates, matches a credential
route, decrypts the secret, injects it as the configured header, forwards
upstream, and scrubs the credential from the response.

This package is a thin, dependency-light `fetch` wrapper that computes exactly
the headers the proxy expects.

## Usage

```ts
import { StewardProxyClient } from "@stwd/proxy-client";

const client = new StewardProxyClient({
  proxyUrl: "https://proxy.example.com",
  token: agentJwt,            // api:proxy-scoped JWT
  signingSecret: signingKey,  // required when the proxy enforces request signing
  tenantId,                   // bound into the signature (must match JWT claims)
  agentId,
});

// Generic signed request. The path is proxy-relative (alias or /proxy/<host>/...).
const res = await client.fetch("/openai/v1/chat/completions", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }),
});

// Liveness probe (unauthenticated).
const health = await client.proxyHealth();
```

## What the client does

- attaches `Authorization: Bearer <token>`
- auto-generates an `Idempotency-Key` (UUID) for `POST`/`PUT`/`PATCH`/`DELETE`
  when the caller did not supply one
- when `signingSecret` is set, computes `X-Steward-Signature` +
  `X-Steward-Request-Timestamp` using the proxy's canonical form

## Signing

The canonical request form and HMAC live in `src/signature.ts`. They mirror the
proxy verifier (`@stwd/proxy`, `middleware/auth.ts`). Golden-vector tests in
`src/__tests__/signature.test.ts` sign identical inputs with both this client
and the proxy's own signer and assert byte-equality, so the two cannot drift.

For signed requests, pass a pre-serialized body (`string` / `Uint8Array` /
`ArrayBuffer`). Serialize objects with `JSON.stringify` before calling.

## Notes

- This is a generic HTTP client by design. There is no vendor-specific helper.
- `requireHttps` defaults to `true` under `NODE_ENV=production`; set it `false`
  for local http proxies in dev/test.
