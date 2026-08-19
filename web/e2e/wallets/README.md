# Headful wallet e2e tests

These specs run the **real** MetaMask and Phantom browser extensions via
[Synpress](https://synpress.io). They live in a separate Playwright project
(`wallets`) and are excluded from the cross-browser `chromium`/`firefox`/
`webkit` projects because Firefox and WebKit can't load arbitrary extensions.

## One-time setup

1. Install the pinned workspace dependencies and Playwright Chromium:

   ```sh
   bun install --frozen-lockfile
   cd web && bunx playwright install chromium
   ```

2. Provision four environment variables for dedicated, empty test wallets:

   - `E2E_METAMASK_SEED_PHRASE`
   - `E2E_METAMASK_PASSWORD` (at least 12 characters)
   - `E2E_PHANTOM_SEED_PHRASE`
   - `E2E_PHANTOM_PASSWORD` (at least 12 characters)

   Never use a live or funded wallet. The preflight reports missing variable
   names without printing their values:

   ```sh
   bun run test:e2e:wallets:preflight
   ```

3. Prime the ignored local wallet caches. The two commands deliberately use
   separate setup roots because Synpress runs every setup file beneath the
   directory it receives. Phantom is downloaded from its Chrome Web Store ID;
   Synpress 4.1.2's legacy Phantom backup hostname is no longer available:

   ```sh
   bun run test:e2e:wallets:cache
   ```

4. Run the headful suite. Its Playwright global setup provisions isolated API
   and web services; Synpress launches Chromium with the cached extensions:

   ```sh
   bun run test:e2e:wallets
   ```

Use `bun run test:e2e:wallets:list` for a dependency and collection check that
does not download extensions or start services. The actual wallet suite is
intentionally separate from `test:e2e:all` because browser extensions require
a graphical Chromium session.

## Cross-platform notes

- **macOS / Windows**: headful runs use the OS display directly.
- **Linux CI**: wrap with `xvfb-run -a bun run e2e:wallets` for a virtual
  display, or use Playwright's `--headed` with `xvfb`.

## Test seed

Credential values are read only from the environment and the generated browser
profiles remain under ignored `web/.cache-synpress/`. Use repository or
environment secrets for the manual workflow; never put seed phrases in source,
workflow YAML, command-line arguments, logs, artifacts, or funded wallets.
