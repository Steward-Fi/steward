# Changelog

All notable changes to `@stwd/react` are documented here.

## Unreleased

### Tests
- Added test coverage for utilities (format, theme, walletPanelRegistry), context hooks (useAuth, useSteward), data hooks (useWallet, useTransactions, useApprovals, usePolicies, useSpend), and SSR branch coverage for the component surface (auth guard, user button, tenant picker, spend dashboard, approval queue, wallet overview, policy controls, email/OAuth callbacks, passkey enrollment). Suite goes from 56 to 195 passing. No source changes.

## 0.9.1

- Security audit hardening release.
- StewardLogin scrubs the magic-link token and email from the URL via history.replaceState after capture, so credentials no longer land in browser history or the Referer header.
