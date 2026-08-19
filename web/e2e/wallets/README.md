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
   directory it receives. The accepted MetaMask release and Phantom Chrome Web
   Store archive are SHA-256 pinned; an extension update fails closed until its
   version and reviewed digest are updated:

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

Credential values are read only from the environment. The manual workflow uses
the protected `wallet-e2e` GitHub environment and exposes them only to the
preflight, profile-build, and real-flow steps. Once the workflow has been
independently reviewed and installed on `develop`, dispatch that trusted
default-branch workflow with the exact 40-character commit SHA to test. A
required environment reviewer should verify that SHA before approving the
credentialed job. The API, web, and fake-provider child processes receive a
sanitized environment. Generated profiles remain under ignored
`web/.cache-synpress/` locally and the workflow removes them and all Playwright
output in its unconditional final step. Never put seed phrases in source,
workflow YAML, command-line arguments, logs, artifacts, or funded wallets.
