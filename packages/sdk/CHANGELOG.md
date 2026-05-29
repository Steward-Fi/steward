# @stwd/sdk Changelog

## Unreleased

- Expands Hyperliquid trade asset types to include NEAR, HYPE, ZEC, XMR.
- Expands Hyperliquid trade asset types to include BNB, SOL, AVAX, ARB, and OP.

## 0.10.0

BREAKING-CHANGES:
- Adds the Sprint 4 trade API surface under `StewardClient.tradeSessions` and `StewardClient.trade.hyperliquid`.
- Consumers that pin exact SDK versions should upgrade to `0.10.0` before using trade session or Hyperliquid order helpers.
