# Repository operating guide

## Setup

- Use Bun 1.3 or newer and install dependencies with `bun install --frozen-lockfile`.
- Target `develop`. Refresh `origin/develop` before final review, and preserve unrelated changes in shared or dirty worktrees.
- Keep secrets in ignored environment files. Start from `.env.example`; never commit real keys, tokens, passwords, recovery material, or production identifiers.

## Validation

- Run the smallest relevant package tests while iterating, then run `bun run lint`, `bun run typecheck`, and the affected test suites.
- `bun run verify` is the deterministic root validation contract. API and proxy E2E commands require the services provisioned in CI; browser suites under `web/e2e` use their own Playwright command.
- Treat a result as current only when it ran against the exact commit being reviewed. Rerun affected checks after rebases, conflict resolution, generated-file updates, or fixups.
- Report local validation, merge state, deployment, and external verification separately.

## Generated files

- Run `bun scripts/generate-openapi.ts` to refresh `docs/openapi.json` and `docs/api-reference/openapi.json` from the runtime contract.
- Run `cd packages/api && bun run openapi` to refresh both OpenAPI documents and generated SDK API types. Commit every generated output with its source change.
- Do not hand-edit lockfiles or generated API outputs; use the owning generator or package manager.

## Database migrations

- Add immutable numbered SQL migrations under `packages/db/drizzle/` and register them in `packages/db/drizzle/meta/_journal.json` through the repository migration workflow.
- Never rewrite an applied migration or add an unnumbered duplicate. Use a new migration for follow-up schema changes.

## Documentation and comments

- Describe current behavior and trust boundaries. Keep change history, PR rationale, and superseded plans in Git history or a clearly historical archive.
- Keep README files, deployment instructions, package manifests, generated contracts, and examples synchronized with the code. Verify relative links when moving documentation.
