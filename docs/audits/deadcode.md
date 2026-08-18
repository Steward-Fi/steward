# Dead-code and dependency audit

## Current evidence

The current production-focused dependency scan is:

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/db \
  bunx knip@6.4.1 --production --include dependencies,unlisted,duplicates --no-progress
```

After the verified removals below, Knip reports nine dependency rows and three
duplicate-export groups. Every reported row/group has been inspected; there are
no unexamined or deferred findings. Knip exits non-zero because the retained
monorepo entrypoints and semantic aliases remain visible to its static model.

## Verified removals

- `packages/seed/package.json`: removed unused `@stwd/vault`.
- `packages/venue-polymarket/package.json`: removed unused `@stwd/shared`,
  `@polymarket/builder-relayer-client`, and `ethers`.
- `packages/plugin-trading/package.json`: moved test-only `drizzle-orm` from
  `dependencies` to `devDependencies`.
- `packages/api/src/services/waifu-bridge.ts`: removed an unreferenced internal
  service.
- `web/src/components/auth-wrapper.tsx`, `dashboard-nav.tsx`, and
  `wallet-provider.tsx`: removed unreferenced or superseded components.
- `web/src/lib/auth-api.ts` and `wagmi.ts`: removed superseded, unreferenced
  helpers.

The lockfile was regenerated from the workspace manifests after these changes.

## Retained dependency findings

### Root integration dependencies

The root manifest is also the runtime for repository scripts and cross-workspace
integration checks, which Knip does not model as package entrypoints in this
production-only mode.

- `@stwd/attestation`: imported by `scripts/check-attestation.ts`.
- `@stwd/venue-hyperliquid`: imported by `scripts/sweep-builder-fees.ts`.
- `viem`: imported by `scripts/e2e-harness.ts`,
  `scripts/sweep-builder-fees.ts`, and its script tests.
### Runnable private packages

Knip does not follow the `start`/`dev` entrypoints of these private packages in
the selected production scan, but the imports are direct and load-bearing:

- `packages/agent-trader`: `@stwd/sdk`, `@stwd/shared`, `ioredis`, and `viem`
  are imported from `src/index.ts`, `webhook.ts`, `webhook-delivery-store.ts`,
  `loop.ts`, `trade-builder.ts`, and `state.ts`.
- `packages/examples/waifu-integration`: `@stwd/sdk` and `@stwd/shared` are
  imported directly by `src/index.ts`; the package runs that file through its
  `start` and `dev` scripts.

## Retained duplicate exports

- `ACCESS_TOKEN_EXPIRY` and `IDENTITY_TOKEN_EXPIRY` are distinct semantic JWT
  policy names. Identity-token signing consumes the latter; access-token paths
  consume the former.
- `stewardPlugin` and the default export intentionally expose the same Eliza
  plugin through named and conventional default-import package APIs.
- Hyperliquid's `signedOrderSchema`, `signedSendAssetSchema`,
  `signedUsdSendSchema`, `signedApproveBuilderFeeSchema`, and
  `signedUpdateIsolatedMarginSchema` intentionally name the common signed
  envelope by operation. The operation-specific names are used at their
  respective parsing and submission boundaries.

## Lockfile integrity

`bun install --lockfile-only` regenerated `bun.lock`. Neither `knip` nor a
`bunx` cache package appears in a workspace manifest or lockfile workspace
dependency list; the pinned scanner remains an ephemeral audit tool.
