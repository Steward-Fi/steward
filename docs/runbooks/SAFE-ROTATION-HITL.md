# Safe 2-of-3 Rotation — Shadow's Live Checklist (one page)

Full context: [`SAFE-ROTATION.md`](./SAFE-ROTATION.md). This page is ONLY what Shadow
does live. Everything else Sol preps or verifies. Budget: **30 minutes**,
**2–3 hardware signatures total**.

## Answer async BEFORE the session (1 line)

> Do you control both `0xdc78E5230d5e55B98a199919109F126752c22EDE` and
> `0x51d6Db671d5F7d50E0636D5C1490994b9d1295aB`? (they are the other 2 owners of the
> existing platform Safe `0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c`)

- **Yes to both → Path 1** (reuse existing Safe, swap the burner owner out).
- **No / unsure → Path 2** (deploy a fresh 2-of-3 fee Safe).

## Bring to the session

- Hardware wallet (Ledger/Trezor), unlocked BNB Chain app.
- Phone with Safe Mobile (or Rabby) holding a **fresh** signer key.
- Railway dashboard access (waifu.fun api + bundle-bot, waifu-core api).
- ~0.01 BNB on the mobile account for gas + dust tests.

## The 30 minutes

| Time | You do | Signatures |
|---|---|---|
| 0–5 | Paste your hardware address + mobile signer address into the channel | 0 |
| 5–12 | Path 1: sign `swapOwner(burner → hardware)` on the existing Safe (app.safe.global, BNB Chain), co-sign with an existing owner key. Path 2: create the Safe (Sol prefills owners + threshold 2), sign the deploy tx | 1 HW |
| 12–15 | Wait: Sol verifies owners/threshold/singleton onchain, posts reads | 0 |
| 15–20 | Send 0.001 BNB dust from mobile to the Safe, then sign a 0.0005 BNB dust-out Safe tx on hardware (Sol or mobile co-signs) | 1 HW |
| 20–25 | Flip Railway env vars exactly as Sol dictates (`WAIFU_PLATFORM_FEE_WALLET`, `PLATFORM_COMMISSION_RECEIVER`, `PLATFORM_RECEIVER` on 3 services), redeploy | 0 |
| 25–30 | Watch `check-fee-wallet.ts` env-check go green, then approve the burner sweep tx (burner → Safe, leaves 0.005 BNB gas reserve) | 0–1 HW |

## Abort rules (any step)

- Verification read disagrees with what Sol predicted → STOP, no more signatures.
- A tx needs a signature Sol did not pre-announce in this checklist → STOP.
- Env flip can always be reverted to the burner address; both addresses are ours.

## Not happening in this session

- No contract deployments beyond the (optional) Safe proxy.
- No private key ever leaves a device. Sol never sees any key material.
- Old burner key is archived offline afterwards (legacy split vaults still stream to
  it and need periodic sweeps), NOT destroyed.
