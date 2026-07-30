# Fee-Wallet Rotation to Safe 2-of-3 (BSC) — Executable Runbook

**Scope:** rotate the waifu.fun platform fee wallet
`0xC9846a839c4e1D9050Dc890A25661AB13224e9EC` (BSC, single-key hot burner, "Sol hot BSC")
to a Gnosis **Safe 2-of-3** smart account.
**Status:** PREP COMPLETE — nothing in this document has been executed onchain.
**Mode:** the live ceremony is HITL (Shadow present, hardware wallet in hand). Target
session length: **~30 minutes** (see §8 checklist).
**Parent decision:** `D1-MPC-DECISION-2026-07-30.md` (steward projects dir) — Safe 2-of-3 now,
FROST threshold signer later behind the same Safe via EIP-1271.

> Verification data in this doc (balances, owners, code hashes) was read from BSC mainnet
> on **2026-07-30** via `https://bsc-dataseed.binance.org/`. Re-run
> `bun run scripts/check-fee-wallet.ts` before the ceremony to refresh.

---

## 1. Current-state audit (what flows in, what breaks, every config location)

### 1.1 The wallet today

| Fact | Value (verified 2026-07-30) |
|---|---|
| Address | `0xC9846a839c4e1D9050Dc890A25661AB13224e9EC` |
| Type | EOA, single hot key (burner) |
| Balance | ~0.02 BNB |
| Nonce | 127 (active history) |
| Roles beyond "fee wallet" | see §1.4 — it is overloaded |

### 1.2 What flows INTO it

1. **Flap agent-treasury launches (waifu.fun + waifu-core):** the Flap adapter
   (`packages/launchpad/src/adapters/flap/placeholder.ts`) deploys a Flap **Split Vault**
   per launch with recipients `[{platform: WAIFU_PLATFORM_FEE_WALLET, platformCutBps},
   {agent treasury, remainder}]`. The platform share of the token tax stream pays this
   address **forever, per already-deployed vault** (recipients are fixed at deploy).
2. **LaunchFactory launches (waifu.fun v2 launch path):** each `createLaunch` deploys an
   immutable `TaxSplitter(platform, patron, agent, ...)` where
   `platform = config.platformReceiver`, and the factory **requires**
   `config.platformReceiver == platformCommissionReceiver` (immutable constructor arg).
   On BSC mainnet that immutable is **already the platform Safe**
   `0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c`
   (`packages/contracts-evm/deployments/bsc-mainnet.json`), NOT the burner. So the
   factory path is already Safe-destined; the burner exposure is the **Flap adapter
   path + anything paying the env address directly**.
3. **Ad-hoc / historical:** manual transfers, test flows, WAIFU eligibility snapshot
   entries reference it.

### 1.3 Every config location that must change (or explicitly must NOT)

**CHANGE at cutover (env, Railway prod + any staging that should mirror):**

| Location | Key | Repo/file receipts |
|---|---|---|
| Railway `waifu.fun` api service | `WAIFU_PLATFORM_FEE_WALLET` | read in `packages/launchpad/.../flap/placeholder.ts:102`, `apps/api/src/routes/v2/agents.ts:1399` (provision adapter `platformWallet`) |
| Railway `waifu.fun` api service | `PLATFORM_COMMISSION_RECEIVER` (falls back to `WAIFU_PLATFORM_FEE_WALLET`) | `apps/api/src/routes/v2/agent-launches.ts:1005`, `apps/api/src/services/bundle-submitter.ts:129` |
| Railway `waifu.fun` api service | `PLATFORM_RECEIVER` (falls back to `WAIFU_PLATFORM_FEE_WALLET`, then commission receiver) | `apps/api/src/routes/v2/agent-launches.ts:1008` — **must equal the LaunchFactory immutable** `0x0985cCC0…9c3c` or `createLaunch` reverts `InvalidPlatformReceiver` |
| Railway `waifu.fun` bundle-bot service | `PLATFORM_COMMISSION_RECEIVER` / `WAIFU_PLATFORM_FEE_WALLET` | `apps/bundle-bot/src/submitter/index.ts:141` |
| Railway `waifu-core` api service | `WAIFU_PLATFORM_FEE_WALLET` | `waifu-core/.env.example:31`, `waifu-core/apps/api/.env.example:16` |
| `.env.example` files (both repos) | same keys | docs hygiene, follow-up PR after cutover |
| Staging box `/opt/.env.staging` | `WAIFU_PLATFORM_FEE_WALLET` | `STAGING_DEPLOYMENT.md` currently pins the burner — point at a **staging** Safe or leave testnet-only |

**DO NOT change (different roles that happen to share the address):**

| Location | Why leave it |
|---|---|
| `packages/contracts-evm/deployments/bsc-mainnet.json` `deployer` | historical fact, record of who deployed |
| `apps/api/src/data/waifu-eligibility.ts`, frontend `waifu-eligibility.json` | immutable airdrop snapshot data |
| `packages/db/src/scripts/backfill-agent-wallets.ts` (`SOL_HOT_BSC_ADDRESS`) | backfill of historical wallet rows |
| `apps/api/src/scripts/backfill-sol.ts` (`SOL_PATRON_ADDRESS` default) | patron identity backfill; revisit separately |
| `eliza-client.ts` `ELIZA_CLOUD_PLATFORM_STEWARD_USER_ID` = `wallet:evm:0xc9846a…` | this is a **Steward/eliza-cloud identity claim**, not a funds destination. Rotating it breaks platform-org auth. Separate migration if ever needed. |

**CANNOT change (immutable onchain) — accept and monitor:**

- Every already-deployed Flap **Split Vault** with the burner as platform recipient
  keeps streaming there. Post-rotation, the old address must be **swept periodically**
  until those streams decay, or the burner key retired to a sweep-only role (§6 step 7).
- Every already-deployed `TaxSplitter` — platform recipient immutable (but on mainnet
  these already point at the Safe `0x0985…`).
- `LaunchFactory.platformCommissionReceiver` immutable = `0x0985…` (fine — it's the Safe).

### 1.4 CRITICAL finding: a platform Safe already exists, and the burner is one of its owners

`0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c` on BSC is a **Safe v1.4.1** (singleton
`0x29fcB43b…C762` in slot 0, `VERSION()` = "1.4.1"), **threshold 2**, owners:

1. `0xC9846a839c4e1D9050Dc890A25661AB13224e9EC` ← **the hot burner we are rotating away from**
2. `0xdc78E5230d5e55B98a199919109F126752c22EDE` (labeled "patron (waifu)" in repo test data; EOA, ~0.048 BNB)
3. `0x51d6Db671d5F7d50E0636D5C1490994b9d1295aB` (EOA, 0 balance, unknown label)

Safe nonce = 3, balance ~0.207 BNB. It is the LaunchFactory `factoryOwner` and
`platformCommissionReceiver`.

**Implication:** compromise of the burner today = 1 of 2 required Safe signatures.
The rotation must therefore do TWO things, not one:

- **(a)** stop routing new fee flow to the burner (env flip), and
- **(b)** `swapOwner` the burner OUT of the existing platform Safe.

---

## 2. Target design decision

Two viable paths. **Recommendation: Path 1** unless Shadow cannot attest control of
the other two existing Safe owners.

### Path 1 (recommended): consolidate on the existing Safe `0x0985…9c3c`

- Set `WAIFU_PLATFORM_FEE_WALLET` (and friends) = `0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c`.
- `swapOwner`: burner out, Shadow **hardware key** in. Resulting owner set =
  hardware + the two verified existing keys, threshold 2.
- Pros: zero new deployments, LaunchFactory paths already point here, one treasury.
- Cons: requires Shadow to positively identify/control `0xdc78…` and `0x51d6…`
  **before** the ceremony (HITL question #1). If either is lost/unknown → Path 2.

### Path 2: deploy a fresh dedicated fee Safe 2-of-3

Use when existing-owner control is unverifiable, or Shadow wants fee custody separated
from factory ownership. Deployment details in §3.

Either way the end state is: **2-of-3 Safe, no hot single key in the fee path, burner
demoted to sweep-only then retired.**

### Signer topology (both paths)

| Slot | Key | Custody |
|---|---|---|
| 1 | Shadow hardware wallet (Ledger/Trezor) | cold, ceremony + approvals only |
| 2 | Shadow mobile signer (Safe Mobile app or Rabby mobile, fresh key) | warm, second factor for routine ops |
| 3 | Sol operational key | see below |

**Sol key custody options (tradeoff table):**

| Option | Blast radius if Sol host compromised | Ops friction |
|---|---|---|
| A. Plain keystore on Sol host | 1 of 3 owners (threshold still holds) | lowest |
| B. Steward vault custody (`@stwd/vault` AES/scrypt or KMS envelope backend) | key never plaintext at rest; decrypt-at-sign | low |
| C. **FROST 2-of-3 sub-shares** for the "Sol" owner slot via `@stwd/signer-frost` (D2 prototype), surfaced to the Safe as one EIP-1271/owner key later | Sol's owner key itself never assembles | highest, blocked on D2 productionization |

**Recommendation:** start with **B** now, migrate slot 3 to **C** when the D2 FROST
sidecar + Safe EIP-1271 verification lands (this is the D1 roadmap). The Safe owner
set change for that future migration is a routine `swapOwner`, not a re-rotation.

**Why 3 human keys was rejected:** Shadow is a single operator; a third human key is
a fiction (it would live on the same laptop as key 2). A Sol operational key gives
genuine second-party availability (Sol can co-sign sweeps/routine ops with Shadow's
mobile) while hardware key stays cold. Threshold 2 means Sol alone can never move funds.

---

## 3. Safe deployment plan on BSC (Path 2 or staging rehearsal)

### 3.1 Canonical addresses — VERIFIED onchain (BSC chainid 56, 2026-07-30, `eth_getCode` non-empty)

Source of truth: [`safe-global/safe-deployments`](https://github.com/safe-global/safe-deployments)
`src/assets/v1.4.1/*.json` (canonical deployment set; chain 56 = "canonical"), cross-checked
against BSC RPC:

| Contract | v1.4.1 canonical address (live on BSC ✓) |
|---|---|
| `SafeProxyFactory` | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` |
| `SafeL2` (singleton) | `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762` |
| `CompatibilityFallbackHandler` | `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99` |
| `MultiSendCallOnly` | `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` |

v1.5.0 is also live on BSC (`SafeL2 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e`,
factory `0x14F2982D601c9458F93bd70B218933A6f8165e7b`), but **use v1.4.1**: it matches
the existing platform Safe, the in-repo `AgentSafeDeployer` pins (waifu.fun
`AgentSafeDeployer.sol:26-27`), and has the longest audit/battle-test history.

### 3.2 Deployment method

Use the official **Safe web app** (`https://app.safe.global`, network = BNB Chain) during
the HITL session — it drives the canonical `SafeProxyFactory.createProxyWithNonce` with
the v1.4.1 singleton and is the least-code path. Inputs:

- Owners: hardware addr, mobile addr, Sol op addr (all collected in §8 pre-flight).
- Threshold: **2**.
- Fallback handler: default (`CompatibilityFallbackHandler` above).
- No modules, no guard at deploy time.

Deployer/gas payer: Shadow's hardware or mobile account (~0.003 BNB). Do NOT pay
deployment from the burner (keeps forensic separation).

### 3.3 Post-deploy onchain verification (before any funds move)

```bash
# 1. proxy points at v1.4.1 SafeL2 singleton (slot 0)
cast storage <NEW_SAFE> 0 --rpc-url https://bsc-dataseed.binance.org
#   expect ...29fcb43b46531bca003ddc8fcb67ffe91900c762

# 2. owners + threshold
cast call <NEW_SAFE> "getOwners()(address[])"   --rpc-url https://bsc-dataseed.binance.org
cast call <NEW_SAFE> "getThreshold()(uint256)"  --rpc-url https://bsc-dataseed.binance.org  # expect 2
cast call <NEW_SAFE> "VERSION()(string)"        --rpc-url https://bsc-dataseed.binance.org  # expect 1.4.1
```

(No `cast`? `bun run scripts/check-fee-wallet.ts --address <NEW_SAFE>` performs the
same reads via raw JSON-RPC.)

---

## 4. Rotation ceremony — step-by-step (with verify + rollback per step)

Notation: `SAFE` = final fee Safe (existing `0x0985…` after owner swap, or fresh deploy),
`BURNER` = `0xC984…e9EC`.

| # | Step | Verify | Rollback |
|---|---|---|---|
| 1 | **Pre-flight** (no txs): run `check-fee-wallet.ts`; snapshot burner + Safe balances, owners, env values; confirm signer devices ready | script output saved to receipt | n/a |
| 2 | **Owner fix** — Path 1: Safe tx `swapOwner(prevOwner, BURNER, HW_ADDR)` on `0x0985…`, signed by 2 existing owners. Path 2: deploy fresh Safe per §3.2 | §3.3 reads: owner set correct, threshold 2, burner absent | Path 1: `swapOwner` back (2 sigs). Path 2: abandon proxy, nothing routed yet |
| 3 | **Dust test IN**: send 0.001 BNB from Shadow mobile → `SAFE` | balance read shows +0.001 | none needed (dust) |
| 4 | **Dust test OUT**: Safe tx sending 0.0005 BNB from `SAFE` → Shadow mobile, signed by HW + (mobile or Sol) — this proves the 2-of-3 signing path end-to-end incl. hardware | tx success, balance −0.0005 | none needed (dust) |
| 5 | **Env flip**: in Railway, set `WAIFU_PLATFORM_FEE_WALLET=SAFE` on waifu.fun api, bundle-bot, waifu-core api; set/confirm `PLATFORM_RECEIVER=0x0985cC…` (must stay = factory immutable); redeploy services | `check-fee-wallet.ts` env-match check green; hit provision/launch preview API and confirm returned `platformWallet` = SAFE | set env back to BURNER, redeploy (window: minutes; launches during the window still pay a wallet we control either way) |
| 6 | **Monitor first real fee flow**: next agent-treasury launch's Split Vault must list `SAFE` as platform recipient; watch first tax split land | vault recipients via launch receipt events; balance increment on SAFE | if a launch deployed with wrong recipient: that single vault's platform share is misrouted — halt launches (env revert), diagnose before more deploys |
| 7 | **Decommission BURNER (sweep + archive)**: sweep BNB minus 0.005 gas reserve → SAFE; enumerate ERC20s (bscscan token holdings) and sweep any nonzero; keep the key **archived offline** (encrypted, labeled "sweep-only: legacy split vaults still stream here"), NOT destroyed | burner balance ≈ gas reserve; sweep txs confirmed | n/a (sweeps go to the Safe we control) |
| 8 | **Post-rotation receipts**: update `.env.example`s (both repos, follow-up PR), append ceremony receipt with tx hashes, update `SOVEREIGN-CUSTODY-STATE.md` | PR links + receipt file | n/a |

**Why the burner key is archived, not destroyed:** already-deployed Flap Split Vaults
stream the platform cut to `BURNER` immutably (§1.3). Until those decay to dust, a
periodic sweep (burner → SAFE) is required. Schedule: monthly cron check via
`check-fee-wallet.ts`, sweep when balance > 0.02 BNB. Long-term: this sweep authority
is exactly what should move into a Steward-custodied capability (broker-mode, spend-limited).

---

## 5. What this rotation does NOT fix (explicit non-goals)

- `LAUNCH_FACTORY_SIGNER_PK` — separate hot signer for launch orchestration. Own lane.
- `ELIZA_CLOUD_PLATFORM_STEWARD_USER_ID` identity claim (§1.3) — untouched.
- Existing Split Vault / TaxSplitter immutables — monitored, not migrated.
- FROST/threshold signing for the Safe owner slot — D2 follow-on, designed for in §2.

---

## 6. Helper script

`scripts/check-fee-wallet.ts` (this repo, read-only, zero deps, raw JSON-RPC):

```bash
bun run scripts/check-fee-wallet.ts                       # audit burner + platform safe
bun run scripts/check-fee-wallet.ts --address 0x...       # audit any address
EXPECTED_FEE_WALLET=0x... WAIFU_PLATFORM_FEE_WALLET=0x... bun run scripts/check-fee-wallet.ts   # env-match check
BSCSCAN_API_KEY=... bun run scripts/check-fee-wallet.ts   # + recent inflow listing
```

Reports: balance, nonce, contract-vs-EOA, Safe detection (version/owners/threshold via
`eth_call`), env config match, and (with an API key) recent incoming txs. **No signing
capability, no private key handling, ever.**

---

## 7. Rollback philosophy

Every fee-flow change is an env var pointing at one of two addresses **we control at
all times**. The only irreversible acts are onchain owner changes, which are themselves
2-of-3 gated and performed before any flow depends on them. There is no step in this
runbook where funds can land at an address controlled by neither party.

---

## 8. HITL checklist — Shadow's 30 minutes

**Pre-flight (Sol does before the session, no Shadow time):** fresh `check-fee-wallet.ts`
output, Railway env screenshots, Sol op key generated into Steward vault (option B),
this checklist printed into the session channel.

**Question to answer BEFORE the session (async, 1 line):**
Do you control `0xdc78E5230d5e55B98a199919109F126752c22EDE` and
`0x51d6Db671d5F7d50E0636D5C1490994b9d1295aB` (the other two owners of platform Safe
`0x0985cC…9c3c`)? → yes to both = Path 1, otherwise Path 2.

| Time | Shadow does | Device |
|---|---|---|
| 0–5 min | Confirm signer addresses: hardware account addr, fresh mobile signer addr | hardware + phone |
| 5–12 min | Path 1: sign `swapOwner` (burner→hardware) in Safe app, second sig from mobile/existing owner. Path 2: create Safe in app.safe.global (owners+threshold prefilled by Sol), sign deploy tx | hardware |
| 12–15 min | Sol verifies onchain (§3.3), reads results into channel | — |
| 15–20 min | Dust in (mobile send), dust out (sign Safe tx on hardware, Sol or mobile co-signs) | phone + hardware |
| 20–25 min | Flip 4 Railway env vars (Sol dictates exact key=value), redeploy | laptop |
| 25–30 min | Watch `check-fee-wallet.ts` env-match go green; approve burner sweep tx | laptop + hardware |

Hardware wallet touches: **2–3 signatures total**. Everything else is verification
Sol performs read-only in front of him.
