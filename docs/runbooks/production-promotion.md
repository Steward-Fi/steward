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
  as code.
- Set `PRODUCTION_RAILWAY_HEALTH_URL` to a credential-free public HTTPS root.
  The deploy script accepts a release only after both `/health` and `/ready`
  succeed.
- Keep production pinned to `repository@sha256:<digest>`. Never repoint it to a
  branch or release tag.

## Promote

1. Deploy the exact `develop` candidate to staging and record its commit and
   image digest. Wait for Railway's `/health` gate and the deploy script's
   `/ready` probe.
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
   valid `sha256` digest.
7. Approve the protected `Production` environment. Record the commit, resolved
   digest, Railway deployment ID, `/health`, and `/ready` receipts.

The `sha-<commit>` tag is used only to find the manifest produced by the exact
main build. Railway receives the resolved digest, not the tag.

## Roll back

1. Select the last known-good full commit SHA that is already on `main` and
   whose exact `main` Docker run succeeded. Confirm that its schema is backward
   compatible with the currently applied migrations. Database rollback is a
   separate, explicitly reviewed operation; never infer it from an image
   rollback.
2. Dispatch **Deploy Railway (Production)** with that SHA. The same provenance,
   digest, Railway status, `/health`, and `/ready` gates apply to rollback.
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
- A deployment that Railway marks successful still fails acceptance unless the
  public `/health` and durable `/ready` probes pass within their timeouts.
- Failed promotion does not authorize a production configuration mutation or a
  database downgrade. Escalate with the captured diagnostics and keep the last
  known-good digest live.
