# Steward Vision

Steward is an open-source, self-hostable governed credential proxy and policy and approval layer for agent provider actions and wallets. It ships scoped grants, exact-request approval, policy-bound execution authorization on the primary EVM sign path, and signed audit evidence verifiable offline.

## Mission

Agents should receive narrowly scoped authority without receiving the underlying provider credential or wallet key.

Agents increasingly sign transactions and call private APIs. Giving an agent a standing secret expands the blast radius of prompt injection, compromised dependencies, and leaked logs. Steward reduces that exposure through configured credential routes, scoped capability grants, wallet policy and approval workflows, and evidence that operators can export and verify outside the running service.

Steward's direction is an open authority plane for agent execution. That is an architectural goal, not a claim that every action or execution surface is governed today.

## Current product boundary

Steward currently provides these distinct boundaries:

### Credential proxy

Configured provider calls can receive a stored credential at the proxy instead of in the supported agent process. Capability definitions bind host, path, method, injection settings, and a per-agent grant with expiry and revocation. The proxy does not govern arbitrary network egress.

### Wallet vault

Local wallet keys are encrypted with AES-256-GCM. Optional AWS KMS envelope wrapping, an operator-supplied PKCS#11 wrapping adapter, and an external-custody interface are available. Local and KMS envelope modes expose plaintext key material to the application at sign time. Steward does not claim MPC custody or native HSM signing.

### Policy and approval

Governed API routes evaluate policy before calling their signing or proxy operation. Wallet workflows support approval queues, generic intents, recent-MFA controls, and stale-state checks. Provider capabilities support exact-request approval and resume. Coverage is route-specific and must not be inferred for an unlisted surface.

### Primary EVM execution authorization

The primary EVM transaction sign path and compatible approval replay require a signed, payload-bound, backend-bound, short-lived, single-use authorization immediately before raw signing. This is an earned enforcement claim for that path, not a product-wide signing claim.

### Audit evidence

Steward maintains a tenant-scoped HMAC audit chain and can export Ed25519-signed checkpoints and event bundles. The standalone verifier checks bundles offline against the public key carried in the bundle. Operators must separately match that key to an out-of-band trusted Steward signing key or fingerprint. This detects modification relative to that trust root, but it cannot exclude fabrication by an operator controlling all relevant keys.

## Product direction

The long-term authority plane should answer:

> May this principal perform this exact action, against this scoped resource, using this credential or wallet, under the applicable policy and approval, right now?

Reaching that direction requires explicit enrollment and tests for each claimed execution surface. A broad authority-plane claim is earned only when materially different adapters share a governed boundary, alternate paths are closed for the claimed surfaces, and a real deployment proves the operating model.

Near-term work should deepen the current open and self-hosted product:

- make scoped provider grants and exact-request approvals easier to configure;
- extend execution authorization only through explicit, tested surface enrollment;
- keep the credential, policy, approval, execution, and evidence contracts inspectable;
- publish precise support matrices and trust limits;
- improve self-hosted deployment, backup, restore, rotation, and monitoring guidance;
- integrate external identity, secrets, and custody systems without replacing them.

## Positioning

Steward is not trying to replace an enterprise directory, a generic authorization engine, a secrets manager, or a specialist custody vendor.

- Identity systems establish who the human or agent is.
- Authorization engines can contribute allow or deny decisions.
- Secrets managers and custody systems protect secret or key material.
- Steward connects scoped agent authority, policy, approval, governed execution paths, and exportable evidence for its supported surfaces.

The open-source and self-hostable ethos is part of the security model. Operators can inspect the enforcement code, run the full stack in their own infrastructure, export their data and evidence, and choose their runtime, cloud, identity provider, secrets system, and custodian.

## Deployment

Steward ships two self-hosted modes:

- **Docker:** API, proxy, PostgreSQL, and Redis for a networked deployment.
- **Embedded:** PGLite for local development, CLI agents, and desktop applications.

The modes share much of the API surface, but their operating and security properties differ. Operators should select and test a deployment profile appropriate to their threat model.

## Values

**Open source.** Steward is MIT licensed. Trust-critical contracts and the offline verifier remain inspectable.

**Self-hostable.** Steward runs in operator-controlled infrastructure. Public documentation does not depend on a managed control plane.

**Scoped by default.** Provider capabilities and wallet operations should be bounded to the smallest practical route, action, lifetime, and principal.

**Approval binds the request.** Human review should authorize an exact immutable request, not a reusable blanket permission.

**Enforcement claims are surface-specific.** A governed path may claim only the boundary implemented and tested on that path.

**Evidence is portable.** Operators can export signed evidence, verify it offline, and separately match the bundled public key to a trusted signing key or fingerprint.

**Trust limits are explicit.** Steward does not imply MPC, native HSM signing, operator-proof logs, prompt-injection immunity, or universal action coverage where those properties are not implemented.
