# Headful wallet e2e tests

These specs run the **real** MetaMask and Phantom browser extensions via
[Synpress](https://synpress.io). They live in a separate Playwright project
(`wallets`) and are excluded from the cross-browser `chromium`/`firefox`/
`webkit` projects because Firefox and WebKit can't load arbitrary extensions.

## One-time setup

1. Install Synpress and Playwright browsers:

   ```sh
   cd web
   bun add -d @synthetixio/synpress
   bun run e2e:install
   ```

2. Prime the wallet cache (downloads the MetaMask + Phantom `.crx`s,
   onboards both wallets with a deterministic test seed, snapshots the
   resulting browser-context dir):

   ```sh
   bun run e2e:wallets:cache
   ```

3. Boot the stack and run the headful suite. Synpress launches its own
   chromium context with the cached extensions loaded:

   ```sh
   bun run e2e:wallets
   ```

## Cross-platform notes

- **macOS / Windows**: headful runs use the OS display directly.
- **Linux CI**: wrap with `xvfb-run -a bun run e2e:wallets` for a virtual
  display, or use Playwright's `--headed` with `xvfb`.

## Test seed

Both wallets are seeded with the BIP-39 test vector
`test test test test test test test test test test test junk`.
**Never use this seed for real funds.**
