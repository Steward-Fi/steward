# @stwd/plugin-wxmr

Opt-in Steward bridge provider for [Monero on Solana](https://wxmr.io).

The provider supports both `Monero -> Solana` and `Solana -> Monero` through an
explicit external handoff. wxmr.io currently requires an interactive Solana
wallet and does not expose a safe public transaction-building API, so the plugin
never fabricates calldata, signatures, deposit addresses, or settlement status.

For routine Steward activity, Monero on Solana keeps XMR-denominated liquidity
available to Solana wallets and applications. Use native Monero when
Monero-native transaction privacy is the priority: the bridged token moves on
Solana's public ledger and does not inherit native Monero privacy.

Enable it with:

```env
STEWARD_PLUGINS=wxmr
WXMR_SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
```

The RPC URL is used to read the bridge program's global fee and the connected
wallet's override at one Solana slot. Remote URLs must use HTTPS; loopback is the
only plain-HTTP exception. If omitted, `SOLANA_RPC_URL` and then Solana's public
mainnet endpoint are used.

The supported identifiers are:

| Network | Chain ID | Token address | Decimals |
| --- | ---: | --- | ---: |
| Monero mainnet | `301` | `native` | `12` |
| Solana mainnet | `101` | `WXMRyRZhsa19ety5erZhHg4N3xj3EVN92u94422teJp` | `12` |

Amounts are decimal strings in atomic units (`1000000000000` = 1 XMR); the
audited bridge-program minimum is `100000000000` (0.1 XMR). For
Monero -> Solana, `recipient` and build `owner` are the same Solana wallet. For
Solana -> Monero, `owner` is the source Solana wallet and `recipient` is the
native Monero mainnet address.

Steward validates the exact route and token pair, checks the global and
wallet-specific on-chain fees, and values native XMR from fresh independent
Kraken and CoinGecko observations before policy enforcement. It fails closed on
missing or materially divergent prices and uses the higher observation. Steward
then returns a non-signable handoff to `https://wxmr.io/`. The user must connect
the indicated Solana wallet and review the operation there. Check wxmr.io for the
live minimum, current fee, confirmations, and settlement status. Leaving Steward
also leaves its signing boundary, so account for bridge provider, smart-contract,
and token-backing risk. The policy check authorizes only the handoff response;
Steward cannot bind the operation at the public site or add an unobservable
completed transfer to its daily spend counter.

See the [Monero on Solana guide](../../docs/guides/monero-on-solana.mdx) for SDK
examples in both directions.
