# @stwd/solana-signer

Standard Solana signer shape backed by the Steward governed vault. Gives any
consumer that accepts an external signer (`{ publicKey, signTransaction,
signAllTransactions }`, the wallet-adapter shape and iqlabs-sdk's
`WalletSigner`) a Steward-governed key without exposing key material.

Every signature is one `POST /vault/:agentId/sign-solana` with
`broadcast:false`: policy evaluates server-side on the real transaction bytes,
the signed transaction comes back, and the caller keeps its own send+confirm
path. This package never broadcasts and never sees a private key.

The signer supplies a stable, request-body-bound idempotency key. Retrying the
same serialized transaction after a lost response can therefore recover the
completed non-broadcast signature from Steward's authenticated idempotency
store. Configure Steward with its durable Redis store when retries may reach
different API replicas.

```ts
import { createStewardSolanaSigner } from "@stwd/solana-signer";

const signer = await createStewardSolanaSigner({
  baseUrl: "http://127.0.0.1:3200",
  agentId: "agent-1",
  bearerToken: process.env.STEWARD_AGENT_TOKEN,
  chainId: 102, // devnet; 101 (default) is mainnet
  requestTimeoutMs: 10_000, // covers headers and bounded response consumption
});

const signed = await signer.signTransaction(tx); // same object, signatures filled
```

## Refusals are typed

Policy outcomes surface as `StewardSignerError` with a `kind`:

- `policy_rejected`: the vault said no (403/422); `policyResults` carries the
  failed rules and the message names the reason.
- `pending_approval`: the transaction was queued for a human (202); `txId`
  identifies the approval to act on. A signer cannot block on a human, so this
  is an error by design.
- `auth`: bad or out-of-scope credentials.
- `api`: anything else.

## Loopback bridge for out-of-process consumers

Processes that cannot hold the signer object (the AgentNet MCP stdio server
via its remote-wallet hook) speak a three-endpoint loopback protocol:

```ts
import { createStewardSolanaSigner, startSignerBridge } from "@stwd/solana-signer";

const signer = await createStewardSolanaSigner({ /* as above */ });
const bridge = await startSignerBridge(signer); // 127.0.0.1, ephemeral port
console.log(bridge.url); // hand this to AGENTNET_WALLET_REMOTE
// Pass bridge.token directly into the child process environment; do not log it.
```

- `GET /pubkey` returns `{ address }`
- `POST /sign-transaction` takes `{ transaction }` (base64) and returns the
  signed transaction, base64
- `POST /sign-message` is always 501: Steward signs transactions under policy,
  not raw messages, so message-derived features on the consumer side stay off

A loopback port is reachable by every process on the machine, so the bridge
requires a shared secret in the `x-steward-bridge-token` header of every
request. The secret is `STEWARD_SIGNER_BRIDGE_TOKEN` from the env when set
(export the same var in the consumer process so both sides read one source),
otherwise a fresh random token per session, exposed as `bridge.token`.
Requests without the right header get 401 before the signer is touched. Tokens
must contain at least 32 bytes. There is deliberately no headerless mode:
unrelated local processes and browser CSRF can both reach loopback ports.

The bridge binds only literal `127.0.0.1` or `::1` addresses (never a DNS
hostname), and rejects weak tokens, concurrent signing
requests, and request bodies larger than 16 KiB. Returned transactions are accepted only when the original
message and existing co-signer signatures are unchanged and the declared
Steward public key has supplied a valid Ed25519 signature.

## Blind-signing hints

Transactions whose instructions Steward cannot decode (custom programs) are
rejected fail-closed unless the server operator explicitly enables unsafe blind
signing. In that mode `to`/`value` cannot be verified from transaction bytes and
are caller assertions, not authoritative evidence. Keep that option off for
untrusted bridge consumers. For fully parsed transactions, Steward rejects any
supplied hints that conflict with the parsed transaction.

## Tests

`bun test` runs against a stub Steward API: request recording (headers, JWT
shape, `broadcast:false` on every call), legacy and v0 signing, partial-sig
preservation, refusal propagation for reject/pending/forbidden envelopes, and
the bridge's shared-secret gate (default random token, strong env token, and
wrong or missing headers refused before any vault call).

The suite runs from a clean checkout: every fixture is created in-process
(the stub API binds an ephemeral loopback port), and `test-preload.ts` builds
the `@stwd/sdk` dist entry the signer imports when it is missing or stale, so
`bun install` + `bun test` is the whole setup.
