// Narrow, duck-typed hook imports. We keep wagmi and @solana/* as optional peer
// dependencies, so these modules are only resolved when the consumer has them
// installed. The shim in src/types/wallet-shims.d.ts keeps the compiler honest
// when they are not.
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useWallet } from "@solana/wallet-adapter-react";
import { WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import type { StewardAuthResult } from "@stwd/sdk";
import { useCallback, useContext, useMemo, useState } from "react";
import { useAccount, useDisconnect, useSignMessage } from "wagmi";
import { StewardAuthContext } from "../provider.js";

// ─── Props ───────────────────────────────────────────────────────────────────

export type WalletChains = "evm" | "solana" | "both";

export interface WalletLoginClassOverrides {
  /** Outer container (controls layout / two-column). */
  root?: string;
  /** Per-chain column wrapper. */
  column?: string;
  /** Column heading (EVM / Solana label). */
  heading?: string;
  /** Status line under the connector (address, chain name). */
  status?: string;
  /** The "Sign in with..." action button. */
  signButton?: string;
  /** Inline error row. */
  error?: string;
  /** Muted hint text ("Connect a wallet to continue"). */
  hint?: string;
}

export interface WalletLoginProps {
  /** Which chain family(ies) to render. Defaults to "both". */
  chains?: WalletChains;
  /** Fires after a successful SIWE / SIWS exchange. */
  onSuccess?: (result: StewardAuthResult, kind: "evm" | "solana") => void;
  /** Fires on any wallet, signing, or server error. */
  onError?: (error: Error, kind: "evm" | "solana") => void;
  /** Extra className appended to the root element. */
  className?: string;
  /** Fine-grained className overrides for internal slots. */
  classes?: WalletLoginClassOverrides;
  /** Label for the EVM column. Default: "Ethereum". */
  evmLabel?: string;
  /** Label for the Solana column. Default: "Solana". */
  solanaLabel?: string;
  /** Override the EVM sign button label. Default: "Sign in with {wallet}". */
  evmSignLabel?: (walletName: string | undefined) => string;
  /** Override the Solana sign button label. Default: "Sign in with {wallet}". */
  solanaSignLabel?: (walletName: string | undefined) => string;
}

// ─── Internal: EVM panel ─────────────────────────────────────────────────────

interface PanelProps {
  classes?: WalletLoginClassOverrides;
  onSuccess?: WalletLoginProps["onSuccess"];
  onError?: WalletLoginProps["onError"];
  label: string;
}

function cx(...parts: Array<string | undefined | false>): string {
  return parts.filter(Boolean).join(" ");
}

function EVMPanel({
  classes,
  onSuccess,
  onError,
  label,
  signLabel,
}: PanelProps & { signLabel?: (walletName: string | undefined) => string }) {
  const ctx = useContext(StewardAuthContext);
  const { address, isConnected, connector, chain } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signMessageFn = useCallback(
    async (msg: string) => {
      const sig = await signMessageAsync({ message: msg });
      return sig as string;
    },
    [signMessageAsync],
  );

  const handleSignIn = useCallback(async () => {
    setError(null);
    if (!ctx) {
      const err = new Error("WalletLogin must be used inside <StewardProvider auth={...}>.");
      setError(err.message);
      onError?.(err, "evm");
      return;
    }
    if (!address) {
      const err = new Error("No EVM wallet connected.");
      setError(err.message);
      onError?.(err, "evm");
      return;
    }
    setBusy(true);
    try {
      const result = await ctx.signInWithSIWE(address, signMessageFn);
      onSuccess?.(result, "evm");
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      // Wallet-reject errors come back with useful .message values already.
      setError(err.message || "Sign-in failed.");
      onError?.(err, "evm");
    } finally {
      setBusy(false);
    }
  }, [ctx, address, signMessageFn, onSuccess, onError]);

  const walletName = connector?.name;
  const labelText = signLabel
    ? signLabel(walletName)
    : walletName
      ? `Sign in with ${walletName}`
      : "Sign in";

  return (
    <div className={cx("stwd-wallet-col", classes?.column)}>
      <h3 className={cx("stwd-wallet-heading", classes?.heading)}>{label}</h3>
      <div className="stwd-wallet-connector">
        <ConnectButton
          label="Connect wallet"
          accountStatus="address"
          chainStatus="name"
          showBalance={false}
        />
      </div>
      {isConnected && address && (
        <>
          <div className={cx("stwd-wallet-status", classes?.status)}>
            <span className="stwd-wallet-addr">
              {address.slice(0, 6)}…{address.slice(-4)}
            </span>
            {chain?.name && <span className="stwd-wallet-chain"> on {chain.name}</span>}
          </div>
          <button
            type="button"
            className={cx("stwd-wallet-sign", classes?.signButton)}
            onClick={handleSignIn}
            disabled={busy}
          >
            {busy ? "Signing…" : labelText}
          </button>
          <button
            type="button"
            className="stwd-wallet-link"
            onClick={() => disconnect()}
            disabled={busy}
          >
            Disconnect
          </button>
        </>
      )}
      {!isConnected && (
        <p className={cx("stwd-wallet-hint", classes?.hint)}>Connect a wallet to continue.</p>
      )}
      {error && (
        <div className={cx("stwd-wallet-error", classes?.error)} role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

// ─── Internal: Solana panel ──────────────────────────────────────────────────

function SolanaPanel({
  classes,
  onSuccess,
  onError,
  label,
  signLabel,
}: PanelProps & { signLabel?: (walletName: string | undefined) => string }) {
  const ctx = useContext(StewardAuthContext);
  const wallet = useWallet();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSignIn = useCallback(async () => {
    setError(null);
    if (!ctx) {
      const err = new Error("WalletLogin must be used inside <StewardProvider auth={...}>.");
      setError(err.message);
      onError?.(err, "solana");
      return;
    }
    if (!ctx.signInWithSolana) {
      // SDK build does not expose Solana sign-in yet. Surface a clear message
      // rather than a silent no-op. TODO: remove this branch once @stwd/sdk
      // ships StewardAuth.signInWithSolana (see PR in the auth sweep).
      const err = new Error(
        "Solana sign-in is not available in this build of @stwd/sdk. Upgrade @stwd/sdk to ≥ 0.8.0.",
      );
      setError(err.message);
      onError?.(err, "solana");
      return;
    }
    if (!wallet.publicKey || !wallet.signMessage) {
      const err = new Error("Connected wallet does not support message signing.");
      setError(err.message);
      onError?.(err, "solana");
      return;
    }

    setBusy(true);
    try {
      const publicKey = wallet.publicKey.toBase58();
      const signMessageFn = async (msg: Uint8Array): Promise<Uint8Array> => {
        // Wallet adapters return Uint8Array; some return bs58 strings historically.
        const out = await wallet.signMessage?.(msg);
        if (!out) throw new Error("Wallet returned an empty signature.");
        return out;
      };
      const result = await ctx.signInWithSolana(publicKey, signMessageFn);
      onSuccess?.(result, "solana");
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      setError(err.message || "Sign-in failed.");
      onError?.(err, "solana");
    } finally {
      setBusy(false);
    }
  }, [ctx, wallet, onSuccess, onError]);

  const walletName = wallet.wallet?.adapter?.name;
  const labelText = signLabel
    ? signLabel(walletName)
    : walletName
      ? `Sign in with ${walletName}`
      : "Sign in";
  const addr = wallet.publicKey?.toBase58();

  return (
    <div className={cx("stwd-wallet-col", classes?.column)}>
      <h3 className={cx("stwd-wallet-heading", classes?.heading)}>{label}</h3>
      <div className="stwd-wallet-connector">
        <WalletMultiButton />
      </div>
      {wallet.connected && addr && (
        <>
          <div className={cx("stwd-wallet-status", classes?.status)}>
            <span className="stwd-wallet-addr">
              {addr.slice(0, 4)}…{addr.slice(-4)}
            </span>
          </div>
          <button
            type="button"
            className={cx("stwd-wallet-sign", classes?.signButton)}
            onClick={handleSignIn}
            disabled={busy || !ctx?.signInWithSolana}
          >
            {busy ? "Signing…" : labelText}
          </button>
        </>
      )}
      {!wallet.connected && (
        <p className={cx("stwd-wallet-hint", classes?.hint)}>Connect a wallet to continue.</p>
      )}
      {error && (
        <div className={cx("stwd-wallet-error", classes?.error)} role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

// ─── Public component ────────────────────────────────────────────────────────

/**
 * WalletLogin — first-class Steward wallet sign-in.
 *
 * Supports EVM (wagmi + RainbowKit) and Solana (@solana/wallet-adapter-react).
 * Must live inside a `<StewardProvider auth={...}>` and, for each enabled chain,
 * the matching wallet provider (see `EVMWalletProvider`, `SolanaWalletProvider`).
 *
 * @example
 * <WalletLogin
 *   chains="both"
 *   onSuccess={(res, kind) => console.log("signed in via", kind, res.token)}
 * />
 */
export function WalletLogin(props: WalletLoginProps) {
  const {
    chains = "both",
    onSuccess,
    onError,
    className,
    classes,
    evmLabel = "Ethereum",
    solanaLabel = "Solana",
    evmSignLabel,
    solanaSignLabel,
  } = props;

  const showEvm = chains === "evm" || chains === "both";
  const showSol = chains === "solana" || chains === "both";

  const layoutClass = useMemo(() => {
    if (chains === "both") return "stwd-wallet-root stwd-wallet-root-two";
    return "stwd-wallet-root stwd-wallet-root-one";
  }, [chains]);

  return (
    <div className={cx(layoutClass, classes?.root, className)}>
      {showEvm && (
        <EVMPanel
          classes={classes}
          onSuccess={onSuccess}
          onError={onError}
          label={evmLabel}
          signLabel={evmSignLabel}
        />
      )}
      {showSol && (
        <SolanaPanel
          classes={classes}
          onSuccess={onSuccess}
          onError={onError}
          label={solanaLabel}
          signLabel={solanaSignLabel}
        />
      )}
    </div>
  );
}
