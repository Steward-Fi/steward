# Dead Code Audit

This is a historical audit snapshot, not a current dead-code inventory. Files
removed by the audited branch may have been restored later with new callers.

## Summary
- Knip version + command used: `knip 6.4.1` via `DATABASE_URL=postgres://user:pass@localhost:5432/db bunx knip@latest --production --no-progress`
- Total findings: 107
- Verified dead + removed: 6
- False positives / kept: 4
- Deferred: 97

## Removed
### 1. `packages/api/src/services/waifu-bridge.ts`
- Evidence: knip flagged it as an unused file, and repo-wide grep found no references to `WaifuBridge`, `WAIFU_CHAIN_ID`, `ProvisionAgentResult`, or the file path outside the file itself.
- Risk: low, internal API service file with no imports or route wiring.

### 2. `web/src/components/auth-wrapper.tsx`
- Evidence: knip flagged it as an unused file, and repo-wide grep found no imports of `AuthWrapper` or the file path.
- Risk: low, deprecated compatibility shim inside the app.

### 3. `web/src/components/dashboard-nav.tsx`
- Evidence: knip flagged it as an unused file, and the dashboard layout defines and uses its own local `DashboardNav` instead.
- Risk: low, duplicate component superseded by in-file implementation.

### 4. `web/src/components/wallet-provider.tsx`
- Evidence: knip flagged it as an unused file, and repo-wide grep found no imports of `WalletProvider` or the file path.
- Risk: low, deprecated no-op wrapper inside the app.

### 5. `web/src/lib/auth-api.ts`
- Evidence: knip flagged it as an unused file, and repo-wide grep found no imports of `signInWithPasskey`, `sendMagicLink`, `verifyMagicLink`, or the file path.
- Risk: low, superseded auth helper layer.

### 6. `web/src/lib/wagmi.ts` (later restored)
- Historical result: the audited branch removed this file after finding no callers.
- Current status: `web/src/components/providers.tsx` dynamically imports it and consumes `getWagmiConfig()` and `SOLANA_RPC_URL`, so it is no longer dead code.

## Kept (knip false positives)
### A. `packages/api/src/embedded.ts`
- Why knip flagged: unused file
- Why actually used: launched by `scripts/start-local.ts` via `bun run packages/api/src/embedded.ts`

### B. `scripts/e2e-auth-test.ts`
- Why knip flagged: unused file
- Why actually used: CLI entrypoint from root `test:e2e:auth` script

### C. `scripts/e2e-integration-test.ts`
- Why knip flagged: unused file
- Why actually used: CLI entrypoint from root `test:e2e:integration` script

### D. `scripts/run-e2e-smoke.ts`
- Why knip flagged: unused file
- Why actually used: CLI entrypoint from root `test:e2e:smoke` script

## Deferred (ambiguous)
### Files and exports pending manual verification
- Remaining knip findings require targeted grep verification before removal.
- Intentionally deferred for now:
  - all dependency/devDependency findings
  - all `packages/sdk` and `packages/react` public-surface export findings
  - all test files, config files, generated files, and scripts
  - duplicate export warning in `packages/eliza-plugin/src/index.ts`, likely package-surface noise rather than removable dead code

## Files changed
- `QUALITY_AUDIT.md`
- deleted `packages/api/src/services/waifu-bridge.ts`
- deleted `web/src/components/auth-wrapper.tsx`
- deleted `web/src/components/dashboard-nav.tsx`
- deleted `web/src/components/wallet-provider.tsx`
- deleted `web/src/lib/auth-api.ts`
- deleted `web/src/lib/wagmi.ts` in the audited branch; a later change restored it with live callers
