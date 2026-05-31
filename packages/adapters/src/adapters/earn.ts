/**
 * EarnAdapter — ERC-4626 yield-vault seam.
 *
 * `listVaults`/`getPosition` are read-only. `buildDeposit`/`buildWithdraw` return
 * {@link UnsignedTxIntent}s for the existing signing+policy path. The mock models
 * a simple share-price vault in memory and NEVER signs.
 */

import { AdapterValidationError, type BaseAdapter, type UnsignedTxIntent } from "../types.js";
import { assertChainId, assertEvmAddress, assertUint256 } from "../validation.js";

export interface VaultInfo {
  readonly address: string;
  readonly chainId: number;
  readonly name: string;
  /** Underlying asset (ERC-20) address. */
  readonly asset: string;
  /** Share-price scaled by 1e18 (assets per share). */
  readonly sharePriceRay: string;
  /** Total assets under management in base units. */
  readonly totalAssets: string;
}

export interface VaultPosition {
  readonly vault: string;
  readonly owner: string;
  /** Share balance in base units. */
  readonly shares: string;
  /** Current redeemable asset value in base units. */
  readonly assets: string;
}

export interface DepositRequest {
  vault: string;
  /** Assets to deposit in base units. */
  assets: string;
  owner: string;
}

export interface WithdrawRequest {
  vault: string;
  /** Shares to redeem in base units. */
  shares: string;
  owner: string;
}

export interface ClaimRequest {
  vault: string;
  owner: string;
}

export interface EarnAdapter extends BaseAdapter {
  readonly category: "earn";
  listVaults(chainId: number): Promise<VaultInfo[]>;
  getPosition(vault: string, owner: string): Promise<VaultPosition>;
  buildDeposit(request: DepositRequest): Promise<UnsignedTxIntent>;
  buildWithdraw(request: WithdrawRequest): Promise<UnsignedTxIntent>;
  buildClaim(request: ClaimRequest): Promise<UnsignedTxIntent>;
}

const SHARE_PRICE_SCALE = 10n ** 18n;

interface MockVaultState {
  address: string;
  chainId: number;
  name: string;
  asset: string;
  sharePriceRay: string;
  totalAssets: string;
  // owner(lowercased) -> shares (base units)
  shares: Map<string, bigint>;
}

/**
 * Deterministic in-memory ERC-4626 mock. Two seeded vaults on chain 8453.
 * Share price is fixed (1.05x) so conversions are deterministic and testable.
 */
export class MockEarnAdapter implements EarnAdapter {
  readonly category = "earn" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private vaults = new Map<string, MockVaultState>();

  constructor() {
    this.seed("0x4626000000000000000000000000000000000001", "Mock USDC Vault", 8453, {
      asset: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      sharePriceRay: (SHARE_PRICE_SCALE + SHARE_PRICE_SCALE / 20n).toString(), // 1.05x
    });
    this.seed("0x4626000000000000000000000000000000000002", "Mock WETH Vault", 8453, {
      asset: "0x4200000000000000000000000000000000000006",
      sharePriceRay: SHARE_PRICE_SCALE.toString(), // 1.0x
    });
  }

  private seed(
    address: string,
    name: string,
    chainId: number,
    extra: { asset: string; sharePriceRay: string },
  ): void {
    this.vaults.set(address.toLowerCase(), {
      address,
      chainId,
      name,
      asset: extra.asset,
      sharePriceRay: extra.sharePriceRay,
      totalAssets: "0",
      shares: new Map(),
    });
  }

  private requireVault(vault: string): MockVaultState {
    const address = assertEvmAddress(vault, "vault");
    const state = this.vaults.get(address.toLowerCase());
    if (!state) {
      throw new AdapterValidationError(`unknown vault: ${address}`);
    }
    return state;
  }

  private sharesToAssets(state: MockVaultState, shares: bigint): bigint {
    return (shares * BigInt(state.sharePriceRay)) / SHARE_PRICE_SCALE;
  }

  private assetsToShares(state: MockVaultState, assets: bigint): bigint {
    return (assets * SHARE_PRICE_SCALE) / BigInt(state.sharePriceRay);
  }

  async listVaults(chainId: number): Promise<VaultInfo[]> {
    const id = assertChainId(chainId);
    return [...this.vaults.values()]
      .filter((state) => state.chainId === id)
      .map(({ shares: _shares, ...info }) => info);
  }

  async getPosition(vault: string, owner: string): Promise<VaultPosition> {
    const state = this.requireVault(vault);
    const ownerAddr = assertEvmAddress(owner, "owner");
    const shares = state.shares.get(ownerAddr.toLowerCase()) ?? 0n;
    return {
      vault: state.address,
      owner: ownerAddr,
      shares: shares.toString(),
      assets: this.sharesToAssets(state, shares).toString(),
    };
  }

  async buildDeposit(request: DepositRequest): Promise<UnsignedTxIntent> {
    const state = this.requireVault(request.vault);
    const owner = assertEvmAddress(request.owner, "owner");
    const assets = assertUint256(request.assets, "assets");

    // Mock accounting only — this does NOT move funds. Real value movement
    // happens only after the unsigned intent is signed+broadcast downstream.
    const assetsBig = BigInt(assets);
    const minted = this.assetsToShares(state, assetsBig);
    const key = owner.toLowerCase();
    state.shares.set(key, (state.shares.get(key) ?? 0n) + minted);
    state.totalAssets = (BigInt(state.totalAssets) + assetsBig).toString();

    return {
      signed: false,
      kind: "evm-tx",
      chainId: state.chainId,
      to: state.address,
      value: "0",
      data: "0x",
      owner,
      category: "earn",
      provider: this.provider,
      metadata: {
        op: "deposit",
        vault: state.address,
        asset: state.asset,
        assets,
        expectedShares: minted.toString(),
      },
    };
  }

  async buildWithdraw(request: WithdrawRequest): Promise<UnsignedTxIntent> {
    const state = this.requireVault(request.vault);
    const owner = assertEvmAddress(request.owner, "owner");
    const shares = assertUint256(request.shares, "shares");

    const sharesBig = BigInt(shares);
    const key = owner.toLowerCase();
    const held = state.shares.get(key) ?? 0n;
    if (sharesBig > held) {
      throw new AdapterValidationError("withdraw shares exceed position");
    }
    const assetsOut = this.sharesToAssets(state, sharesBig);
    state.shares.set(key, held - sharesBig);
    state.totalAssets = (BigInt(state.totalAssets) - assetsOut).toString();

    return {
      signed: false,
      kind: "evm-tx",
      chainId: state.chainId,
      to: state.address,
      value: "0",
      data: "0x",
      owner,
      category: "earn",
      provider: this.provider,
      metadata: {
        op: "withdraw",
        vault: state.address,
        asset: state.asset,
        shares,
        expectedAssets: assetsOut.toString(),
      },
    };
  }

  async buildClaim(request: ClaimRequest): Promise<UnsignedTxIntent> {
    const state = this.requireVault(request.vault);
    const owner = assertEvmAddress(request.owner, "owner");

    return {
      signed: false,
      kind: "evm-tx",
      chainId: state.chainId,
      to: state.address,
      value: "0",
      data: "0x",
      owner,
      category: "earn",
      provider: this.provider,
      metadata: {
        op: "claim",
        vault: state.address,
        asset: state.asset,
      },
    };
  }
}
