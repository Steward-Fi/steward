# Production promotion and rollback

This runbook is the release boundary between the continuously validated
`develop` branch and production. Production must run an immutable image digest
built by the Docker workflow for an exact commit already on `main`. Mutable
tags such as `develop`, `main`, `latest`, and version tags are not production
deployment inputs.

The workflow and scripts are instance-neutral. Each operator supplies its own
Railway service, environment, health origin, token, and optional image
repository through GitHub environment secrets and variables.

## Required controls

- Protect `main`; changes arrive through reviewed pull requests with required
  CI and Docker checks.
- Protect the GitHub `Production` environment with required reviewers.
- Configure Railway's platform health check to use `/health`. The repository's
  `railway.json` declares that path for repository-backed services; verify the
  effective service setting when an image-only service does not consume config
  as code. The production deploy script writes and reads back that setting
  before triggering the release, then requires it in the exact deployment's
  metadata. It also pins `overlapSeconds=0` so the later public `/ready` probe
  cannot be routed to the old deployment after Railway activates the candidate.
  A public `/health` response is not release evidence because the previous
  instance could answer it during cutover.
- Set `PRODUCTION_RAILWAY_HEALTH_URL` to a credential-free public HTTPS root.
  The production workflow fails before its first Railway mutation when this
  value is absent.
- Configure a dedicated `STEWARD_READY_PROBE_TOKEN` on the production Steward
  service and store the same value as the `STEWARD_READY_PROBE_TOKEN` secret in
  the protected GitHub `Production` environment. Configure this Railway
  variable before dispatching the first protected deployment; the deploy itself
  intentionally does not create or change secrets. Before its first Railway
  mutation, the script reads the exact project's rendered variables for the
  selected service/environment and compares the effective value to the GitHub
  secret in-process. It never prints the variables response or either token and
  fails closed on an absent value, target mismatch, query failure, or value
  mismatch. This control-plane bootstrap contract works when the currently
  pinned rollback image predates authenticated verbose `/ready` support.
  Production acceptance still requires HTTP 200 from the candidate's
  authenticated `/ready` plus the full Steward-owned readiness details, so a
  legacy or public sanitized response cannot satisfy the final gate.
- Keep production pinned to `repository@sha256:<digest>`. Never repoint it to a
  branch or release tag.
- A database with the audited 0082-absent/0083-present discontinuity must use
  the separately reviewed [0082–0110 production core repair](production-core-repair-0082-0110.md)
  before an auth-release cutover. Its Steward-owned marker never replaces the
  exact catalog and readiness gates. That repair's old-image receipt validator
  must also pass against the exact approved candidate digest/source and the
  hashed evidence artifact; the pinned production image has a forward-only
  rollback limitation after 0084 and requires provider execution to remain
  drained.

## Promote

1. Deploy the exact `develop` candidate to staging and record its commit and
   image digest. Wait for Railway's `/health` gate.
2. Run the release-specific staging checks, including authentication and any
   migration or provider flows changed by the candidate. Save the receipts.
3. Open a `develop` to `main` promotion pull request. Reconcile `main` back into
   the candidate through a reviewed branch when branch protection reports the
   promotion behind. Do not bypass protection or substitute earlier evidence
   after the head changes.
4. Merge only after all required checks and review are green on the exact
   promotion head.
5. Wait for the `Docker` workflow triggered by the resulting `main` push to
   succeed. Record the full 40-character `main` commit SHA.
6. Dispatch **Deploy Railway (Production)** with that full `main_sha`. Start
   with `dry_run=true` when changing deployment configuration or credentials.
   The workflow fails closed unless the SHA is reachable from `origin/main`,
   an exact-SHA successful `main` Docker run exists, the current manifest's
   provenance names that exact revision and `main`, and the image resolves to a
   valid `sha256` digest. The script sets Railway `healthcheckPath=/health` and
   `overlapSeconds=0`, reads back the effective image and settings, requires a
   new deployment ID returned by `serviceInstanceDeployV2`, and accepts only
   that ID with the
   exact digest and platform health setting in its deployment metadata. It
   snapshots recent deployment IDs before the mutation and fails if an
   auto-deploy or concurrent actor creates any additional deployment during
   the run. It also refuses to start while any baseline deployment is
   nonterminal, repeats the exact control-plane checks after `/ready`, and
   requires the tracked ID to be Railway's sole final active deployment.
7. Approve the protected `Production` environment. Record the commit, resolved
   digest, exact Railway deployment ID, platform `/health` gate, and
   authenticated `/ready` receipt.

The `sha-<commit>` tag is used only to find the manifest produced by the exact
main build. Railway receives the resolved digest, not the tag.

Railway's Deployment API exposes the image and digest but not OCI revision
labels. Revision proof therefore comes from the registry provenance check; the
deployment script verifies the exact-revision lookup tag still resolves to the
same immutable digest before and after reading provenance, then binds Railway's
exact deployment ID to that digest.

## Roll back

1. Select the last known-good full commit SHA that is already on `main` and
   whose exact `main` Docker run succeeded. Confirm that its schema is backward
   compatible with the currently applied migrations. Database rollback is a
   separate, explicitly reviewed operation; never infer it from an image
   rollback.
2. Dispatch **Deploy Railway (Production)** with that SHA. The same provenance,
   digest, Railway status, and `/health` gates apply to rollback.
3. If the previous release cannot pass current readiness, stop. Preserve the
   live healthy deployment, diagnose the incompatibility, and ship a forward
   fix through `develop` and `main`.
4. Record the reason, old and restored digests, deployment IDs, health receipts,
   and follow-up issue. Do not use Railway's branch/tag source selector as a
   shortcut.

## Failure behavior

- A Railway build/deploy failure fails the workflow; an empty-log control-plane
  rejection is also fatal by default.
- A container that never passes `/health` is not eligible for Railway cutover
  when the platform health check is configured.
- A `SUCCESS` status for any deployment other than the exact ID returned to the
  workflow is ignored and cannot satisfy acceptance. The accepted deployment's
  service, environment, image, digest, and embedded `/health` setting must all
  match.
- A deployment that Railway marks successful still fails production acceptance
  unless authenticated `/ready` returns `status: ready` with verbose proof that
  the operator token was accepted, Steward-owned migration mode, the `steward`
  schema, and green core-repair plus auth-schema checks. Readiness response
  bodies are withheld from CI logs because they can contain operator
  diagnostics.
- The workflow mutates the service-instance source and healthcheck setting
  before Railway returns the new deployment ID. A failure after that mutation
  leaves the GitHub deployment red but does not automatically rewrite Railway
  configuration or roll back the image: after a forward-only schema repair, an
  automatic old-image rollback can be unsafe. If the failure occurs before the
  trigger, the previously active deployment remains live while the configured
  source may point at the candidate. If it occurs after Railway reports
  `SUCCESS`, the candidate may already be active. Freeze further mutations,
  inspect the exact deployment ID in the failure output, and follow the explicit
  rollback procedure above only after confirming schema compatibility. A red
  workflow is never a successful release receipt.
- Failed promotion does not authorize a production configuration mutation or a
  database downgrade. Escalate with the captured diagnostics and keep the last
  known-good digest live.
