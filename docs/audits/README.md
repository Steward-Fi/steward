# Code-quality audits

These documents record current repository invariants and the evidence used to retain or remove
code. Historical implementation discussion belongs in git history; an audit is kept here only when
it remains useful for validating the present tree.

## Current audit

- [`repository-quality-2026-08-17.md`](repository-quality-2026-08-17.md) — repository-wide repeated
  review of production behavior, tests, dependencies, documentation, generated contracts,
  migrations, deployment assets, and the live pull-request queue.

## Focused inventories

- [`deadcode.md`](deadcode.md) — pinned dependency/dead-code scan and retained false-positive
  evidence.
- [`dedup.md`](dedup.md) — duplicate implementations and intentional aliases.
- [`circular.md`](circular.md) — package and source dependency-cycle evidence.
- [`types.md`](types.md) and [`weaktypes.md`](weaktypes.md) — public type ownership and remaining
  runtime-boundary rules.
- [`trycatch.md`](trycatch.md) — exception handling and fail-open/fail-closed inventory.
- [`legacy.md`](legacy.md) and [`slop.md`](slop.md) — compatibility and repository-hygiene checks.

Security-specific assessments remain alongside these inventories because their test matrices and
trust-boundary evidence are still operationally useful.
