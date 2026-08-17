# Agent Bootstrap — keypair-only boot (Pillar A / lane A3)

The `@stwd/sdk` **agent client** lets an Eliza/agent process boot holding
**nothing but its P-256 identity keypair** (plus the Steward base URL) and obtain
everything else at runtime: a short-lived agent token via enrollment, its
capability manifest, and either short-lived scoped tokens (token mode) or
brokered calls (broker mode). No long-lived secret ever lands in a cloud env var.

This is the client side of the A1 capability plane
(`/agent-enroll/*`, `/capabilities/manifest`, `/capabilities/:name/invoke`).

---

## The lifecycle

```
 provision keypair  ─────────────────────────────────────────────────────────┐
   (operator, once) generate a P-256 keypair; give the PRIVATE key to the      │
   agent's runtime (mounted file / injected path), register the PUBLIC key.     │
                                                                                │
 register agent_signer  ──────────────────────────────────────────────────────┤
   (operator step) POST the PUBLIC key into `agent_signers`                     │
   (keyType=p256, status=active). This is the ONLY operator action. No token    │
   is ever minted by hand.                                                       │
                                                                                │
 agent boots with keypair ONLY  ───────────────────────────────────────────────┤
   AgentKeypair.fromPkcs8Base64(process.env.STEWARD_AGENT_KEY) — the private     │
   key is imported NON-extractable and is never logged / re-exported.            │
                                                                                │
 enroll()  ────────────────────────────────────────────────────────────────────┤
   POST /agent-enroll/challenge { agentId }  → { nonce, canonicalString }        │
   sign(canonicalString) with the identity key                                   │
   POST /agent-enroll/verify { agentId, nonce, signature } → short-lived token   │
                                                                                │
 manifest()  ───────────────────────────────────────────────────────────────────┤
   GET /capabilities/manifest → the provider:kind[:agent] entries this agent      │
   may request (revoked/absent grants simply do not appear).                     │
                                                                                │
 issue() / invoke()  ────────────────────────────────────────────────────────────┤
   token mode → POST /capabilities/manifest/:id/issue  → short-lived scoped token │
   broker mode → POST /capabilities/:name/invoke        → Steward performs the     │
                 call, injects the credential server-side, returns a scrubbed body │
                 (202 approval-pending is a first-class state, not an exception).  │
                                                                                │
 renewal  ───────────────────────────────────────────────────────────────────────┤
   a background timer re-enrolls a lead-time before expiry (with jitter). On any   │
   failure it FAILS CLOSED: drops the token, emits `unauthenticated`, never reuses  │
   a stale token.                                                                   │
                                                                                │
 revocation  ─────────────────────────────────────────────────────────────────────┘
   operator flips the signer to `revoked` (or revokes the grant). Within one short
   renewal cycle (<5 min) the agent can no longer enroll → it drops to
   unauthenticated automatically. There is NO agent-facing revoke; short TTL +
   fail-closed renewal is the enforcement.
```

---

## Minimal usage

```ts
import { AgentClient, AgentKeypair, bootAgentClient } from "@stwd/sdk";

// The private key is the ONLY long-lived secret the agent holds. Load it from a
// mounted file or an injected env-referenced path — never a plaintext env value
// baked into the image, and never logged.
const keypair = await AgentKeypair.fromPkcs8Base64(process.env.STEWARD_AGENT_KEY!);

// boot = construct + enroll + start the renewal loop, in one call.
const agent = await bootAgentClient({
  baseUrl: process.env.STEWARD_URL!, // e.g. https://steward.example
  agentId: process.env.STEWARD_AGENT_ID!,
  keypair,
});

// what can I do?
const manifest = await agent.manifest();

// broker mode (Discord bot token can't be scoped down → Steward brokers it):
const res = await agent.invoke("discord.send", {
  body: { channelId: "123", content: "gm" },
});
if (res.status === "pending_approval") {
  // first-class state — poll / await out-of-band approval, then re-invoke.
} else {
  console.log(res.data); // scrubbed upstream body; the bot token never touched us
}

// token mode (GitHub App token is natively short-lived + scopable):
const cap = await agent.issue("github:app:acme", {
  ttlSeconds: 3600,
  workspaceId: process.env.STEWARD_WORKSPACE_ID!,
  idempotencyKey: crypto.randomUUID(),
  resource: {
    repositories: ["steward"],
    permissions: { issues: "write" },
  },
});
if (cap.mode === "token") {
  // Delivered once with no-store headers. Steward persists only its digest.
  // Keep it only as long as needed, then revoke with proof of possession:
  await agent.revokeLease(cap.leaseId!, cap.token);
}
```

### Honest failure surface

```ts
agent.on((e) => {
  switch (e.type) {
    case "enrolled":
    case "renewed":
      break; // healthy
    case "renew_failed":
      logger.warn("steward renewal failed", { willRetry: e.willRetry });
      break;
    case "unauthenticated":
      // the client has NO live token right now (fail-closed). Any authed call
      // will throw NotEnrolledError until a renewal succeeds. Degrade gracefully.
      break;
  }
});
```

---

## Contrast with the OLD flow (the trust hole this closes)

| | **Old: operator-minted token** | **New: keypair-only enrollment** |
|---|---|---|
| Boot secret | a **≤30-day** agent JWT (`POST /agents/:id/token`), minted by an admin and baked into the container env | the agent's **P-256 private key only** — no token at rest |
| Where the secret lives | a **long-lived bearer in a cloud env var** (the Railway-class trust hole) | a non-extractable key in the agent process; the server only ever sees the **public** key |
| Rotation | manual, operator re-mints and redeploys | automatic — every ~minutes the token is re-minted via challenge/response |
| Revocation | wait up to 30 days for expiry, or maintain a JWT denylist | flip the signer to `revoked` → agent stops enrolling within **one short cycle (<5 min)** |
| Blast radius if leaked | a stolen token is valid for up to 30 days | a stolen **short-lived** token dies in minutes; the identity key never leaves the agent, so there is nothing 30-day to steal |
| Least privilege | one broad agent token | per-capability short-lived scoped tokens (token mode) or zero-token brokering (broker mode) |

The operator's job shrinks to a single one-time act: **register the public key.**
Everything else is the agent authenticating itself with math it can prove but
never has to hand over.

---

## Security properties (enforced in code)

- **No long-lived secret in the client.** Only the identity key persists; agent
  and capability tokens are minute-scale and re-minted on demand.
- **No raw-key export / no key in logs.** `AgentKeypair` imports the private key
  non-extractable where the runtime allows and exposes only `sign()`;
  `toString`/`toJSON`/inspect are redacted so an accidental `console.log` cannot
  leak it.
- **Fail-closed renewal.** Any renewal failure (network, revocation) drops the
  token and moves to an unauthenticated state; a stale/revoked token is never
  reused.
- **Jittered renewal** de-synchronizes a fleet so agents don't stampede Steward.
- **Clock-skew tolerant** expiry reading for scheduling (the server remains the
  authority on validity).
- **202 approval-pending is a state, not an exception**, so approval workflows
  are first-class rather than error handling.
