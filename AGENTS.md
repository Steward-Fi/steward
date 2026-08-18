# Repository operating guide

## Setup

- Use Bun 1.3 or newer and install with `bun install --frozen-lockfile` when verifying a clean
  checkout.
- Target `develop`. Refresh `origin/develop` before final review, and do not overwrite unrelated
  changes in a shared or dirty worktree.
- Keep secrets in ignored environment files. Start from `.env.example`; never commit real keys,
  tokens, passwords, recovery material, or production identifiers.

## Validation

- Run the smallest relevant package tests while iterating, then run `bun run lint`,
  `bun run typecheck`, and the affected test suites.
- `bun run verify` is the deterministic root validation contract. It includes package and script
  tests. API/proxy E2E commands require the explicitly provisioned services described in CI;
  browser suites under `web/e2e` require their own Playwright command.
- Treat a result as current only when it ran against the exact commit being reviewed. Re-run
  affected checks after a rebase, conflict resolution, generated-file update, or fixup.
- A local pass is not deployment proof. Report merged, deployed, and externally verified states
  separately.

## Generated files

- `bun scripts/generate-openapi.ts` refreshes both committed OpenAPI documents from the runtime
  contract: `docs/openapi.json` is the served document and `docs/api-reference/openapi.json` is the
  Mintlify copy with its local interactive-server override.
- `cd packages/api && bun run openapi` refreshes both OpenAPI documents and then generates the SDK
  API types. Commit all generated outputs with the source change and run the corresponding check.
- Do not hand-edit lockfiles or generated API outputs. Use the owning generator/package manager.

## Database migrations

- Add immutable, numbered SQL migrations under `packages/db/drizzle/` and register them in
  `packages/db/drizzle/meta/_journal.json` through the repository's migration workflow.
- Never add an unnumbered duplicate migration or rewrite an applied migration. Add a new migration
  for follow-up schema changes.

## Documentation and comments

- Describe current behavior and trust boundaries. Put change history, PR rationale, and superseded
  plans in git history or a clearly historical archive.
- Keep README, deployment instructions, package manifests, generated contracts, and examples in
  sync with code. Verify relative links when moving documentation.
