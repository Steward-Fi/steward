import type { StewardAuthResult } from "@stwd/sdk";
import React, { useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  DiscordIcon,
  EmailIcon,
  EthereumIcon,
  GitHubIcon,
  GoogleIcon,
  PasskeyIcon,
  XIcon,
} from "../icons/index.js";
import {
  getEvmWalletPanel,
  getSolanaWalletPanel,
  type WalletPanelLoader,
} from "../internal/walletPanelRegistry.js";
import { StewardAuthContext } from "../provider.js";
import type { StewardLoginProps } from "../types.js";
import type { WalletLoginPanelProps } from "./WalletLogin.js";

type LoginStep = "idle" | "loading" | "email-sent" | "error";
type LoadingButton =
  | "passkey"
  | "email"
  | "google"
  | "discord"
  | "github"
  | "twitter"
  | "siwe"
  | "wallet-evm"
  | "wallet-sol"
  | null;

type WalletPanelComponent = React.ComponentType<WalletLoginPanelProps>;

/**
 * Adapt a `<WalletLogin*>` panel `onSuccess` callback (which yields a full
 * `StewardAuthResult` plus a `kind` discriminator) to the shape consumers of
 * `<StewardLogin>` expect (`{ token, user }`). Exported for direct unit
 * testing of the bubble contract.
 */
export function composeWalletSuccess(
  onSuccess?: StewardLoginProps["onSuccess"],
): NonNullable<WalletLoginPanelProps["onSuccess"]> {
  return (result, _kind) => {
    onSuccess?.({ token: result.token, user: result.user });
  };
}

/**
 * Adapt a `<WalletLogin*>` panel `onError` callback to the shape that
 * `<StewardLogin>` consumers expect. Exported for direct unit testing.
 */
export function composeWalletError(
  onError?: StewardLoginProps["onError"],
): NonNullable<WalletLoginPanelProps["onError"]> {
  return (err, _kind) => {
    onError?.(err);
  };
}

/**
 * Lazily load a `<WalletLogin*>` panel only when it is actually needed.
 *
 * The panels live in `WalletLogin.EVM.tsx` / `WalletLogin.Solana.tsx` so their
 * `wagmi` / `@solana/*` peer-dep imports stay off the root bundle. We mirror
 * the pattern from `<WalletLogin>` itself: dynamic import, fallback while
 * loading. We avoid `React.lazy` here because `renderToString` does not
 * support Suspense.
 */
function useDynamicWalletPanel(
  enabled: boolean,
  loader: (() => Promise<{ default: WalletPanelComponent }>) | undefined,
): WalletPanelComponent | null {
  const [Panel, setPanel] = useState<WalletPanelComponent | null>(null);
  useEffect(() => {
    if (!enabled || !loader) return;
    let cancelled = false;
    loader().then((mod) => {
      if (!cancelled) setPanel(() => mod.default);
    });
    return () => {
      cancelled = true;
    };
  }, [enabled, loader]);
  return Panel;
}

/**
 * StewardLogin, drop-in auth widget for Steward-powered apps.
 *
 * Must be used inside a `<StewardProvider auth={{ baseUrl: "..." }}>`.
 *
 * Supports:
 *   - Passkey (WebAuthn), browser only
 *   - Email magic link
 *   - Wallet sign-in (SIWE / SIWS), via `showWallets`. Requires the matching
 *     wallet provider (see `EVMWalletProvider`, `SolanaWalletProvider` from
 *     `@stwd/react/wallet`).
 *   - Google OAuth (popup)
 *   - Discord OAuth (popup)
 *
 * @example
 * <StewardProvider client={client} agentId="..." auth={{ baseUrl: "https://api.steward.fi" }}>
 *   <StewardLogin
 *     variant="card"
 *     title="welcome back"
 *     showWallets
 *     showGoogle
 *     showDiscord
 *     onSuccess={({ token }) => console.log("signed in:", token)}
 *   />
 * </StewardProvider>
 */
export function StewardLogin({
  onSuccess,
  onError,
  showPasskey = true,
  showEmail = true,
  showSIWE = false,
  showWallets = false,
  showGoogle = true,
  showDiscord = true,
  showGithub = true,
  showTwitter = true,
  variant = "card",
  logo,
  title,
  subtitle,
  tenantId,
  className,
}: StewardLoginProps) {
  const ctx = useContext(StewardAuthContext);

  const [email, setEmail] = useState("");
  const [step, setStep] = useState<LoginStep>("idle");
  const [loadingBtn, setLoadingBtn] = useState<LoadingButton>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Track whether we've already fired onSuccess to avoid double-calling
  const didFireSuccess = useRef(false);

  // Resolve `showWallets` into per-chain booleans. Done before any dynamic
  // import hooks so loader hooks are called unconditionally.
  const wantWalletEvm =
    showWallets === true || (typeof showWallets === "object" && !!showWallets?.evm);
  const wantWalletSolana =
    showWallets === true || (typeof showWallets === "object" && !!showWallets?.solana);

  // Provider feature-detect. Backend reports siwe/siws via GET /v1/auth/providers.
  // Default to false until the backend confirms; we don't want to render wallet
  // buttons during initial load (providers === null) or when discovery failed.
  // This mirrors the OAuth gating pattern used elsewhere in this component.
  const providers = ctx?.providers;
  const siweEnabled = wantWalletEvm && providers?.siwe === true;
  const siwsEnabled = wantWalletSolana && providers?.siws === true;

  // Read panel loaders from the wallet registry. The registry is populated
  // as a side effect when the consumer imports `@stwd/react/wallet`. If they
  // didn't import that subpath, the loaders are undefined and we render no
  // wallet buttons (consistent with optional peer dep contract).
  const evmRegistered = useMemo<WalletPanelLoader | undefined>(
    () => (siweEnabled ? getEvmWalletPanel() : undefined),
    [siweEnabled],
  );
  const solanaRegistered = useMemo<WalletPanelLoader | undefined>(
    () => (siwsEnabled ? getSolanaWalletPanel() : undefined),
    [siwsEnabled],
  );
  const EVMPanel = useDynamicWalletPanel(
    siweEnabled && !!evmRegistered,
    evmRegistered?.load as (() => Promise<{ default: WalletPanelComponent }>) | undefined,
  );
  const SolanaPanel = useDynamicWalletPanel(
    siwsEnabled && !!solanaRegistered,
    solanaRegistered?.load as (() => Promise<{ default: WalletPanelComponent }>) | undefined,
  );

  // When auth state changes to authenticated, fire onSuccess for redirect
  useEffect(() => {
    if (ctx?.isAuthenticated && ctx.session?.token && onSuccess && !didFireSuccess.current) {
      didFireSuccess.current = true;
      const user = ctx.session.user ?? { id: "", email: "" };
      onSuccess({ token: ctx.session.token, user });
    }
  }, [ctx?.isAuthenticated, ctx?.session, onSuccess]);

  // Wallet panel callbacks. Defined before any early return so hook order
  // stays stable across the missing-context branch.
  const handleWalletSuccess = useCallback(
    (result: StewardAuthResult, kind: "evm" | "solana") => {
      setLoadingBtn(null);
      setStep("idle");
      setErrorMsg(null);
      // Mark didFireSuccess BEFORE invoking onSuccess so the auth-state
      // effect (which fires when ctx.isAuthenticated flips) does not
      // double-invoke. The wallet sign helpers already wrote the session
      // into the auth context, so the effect would otherwise see the new
      // authenticated state on its next render and fire again.
      didFireSuccess.current = true;
      composeWalletSuccess(onSuccess)(result, kind);
    },
    [onSuccess],
  );

  const handleWalletError = useCallback(
    (err: Error, kind: "evm" | "solana") => {
      setErrorMsg(err.message || "wallet sign-in failed");
      setStep("error");
      setLoadingBtn(null);
      composeWalletError(onError)(err, kind);
    },
    [onError],
  );

  // Class overrides for the wallet panels so they slot into the card layout
  // and look like siblings of the OAuth buttons.
  const walletClasses = useMemo(
    () => ({
      column: "stwd-login__wallet-col",
      heading: "stwd-login__wallet-heading",
      status: "stwd-login__wallet-status",
      signButton: "stwd-login__btn stwd-login__btn--wallet",
      hint: "stwd-login__wallet-hint",
      error: "stwd-login__error",
    }),
    [],
  );

  if (!ctx) {
    return (
      <div className={`stwd-login stwd-login--error ${className ?? ""}`}>
        <p className="stwd-login__error">
          StewardLogin needs a &lt;StewardProvider&gt; with an <code>auth</code> prop.
        </p>
      </div>
    );
  }

  // Already signed in
  if (ctx.isAuthenticated) {
    return null;
  }

  // Determine which OAuth providers to show based on API + props
  const googleEnabled = showGoogle && (providers?.google ?? false);
  const discordEnabled = showDiscord && (providers?.discord ?? false);
  const githubEnabled = showGithub && (providers?.github ?? false);
  const twitterEnabled = showTwitter && (providers?.twitter ?? false);
  const hasOAuth = googleEnabled || discordEnabled || githubEnabled || twitterEnabled;
  // Wallet UI requires both: backend confirms support AND a panel loader is
  // registered (i.e. consumer imported `@stwd/react/wallet`). Without
  // a registered panel, rendering would show a permanently-disabled
  // loading placeholder, which is worse than hiding the button.
  const evmReady = siweEnabled && !!evmRegistered;
  const solanaReady = siwsEnabled && !!solanaRegistered;
  const hasWallet = evmReady || solanaReady;

  const handleError = (err: unknown) => {
    const error = err instanceof Error ? err : new Error(String(err));
    setErrorMsg(error.message);
    setStep("error");
    setLoadingBtn(null);
    onError?.(error);
  };

  const handlePasskey = async () => {
    if (!email.trim()) {
      setErrorMsg("enter your email first");
      setStep("error");
      return;
    }
    setStep("loading");
    setLoadingBtn("passkey");
    setErrorMsg(null);
    try {
      const result = await ctx.signInWithPasskey(email.trim());
      onSuccess?.(result);
    } catch (err) {
      handleError(err);
    }
  };

  const handleEmail = async () => {
    if (!email.trim()) {
      setErrorMsg("enter your email");
      setStep("error");
      return;
    }
    setStep("loading");
    setLoadingBtn("email");
    setErrorMsg(null);
    try {
      await ctx.signInWithEmail(email.trim());
      setStep("email-sent");
      setLoadingBtn(null);
    } catch (err) {
      handleError(err);
    }
  };

  const handleOAuth = async (provider: "google" | "discord" | "github" | "twitter") => {
    setStep("loading");
    setLoadingBtn(provider);
    setErrorMsg(null);
    try {
      if (typeof ctx.signInWithOAuth !== "function") {
        throw new Error("oauth unavailable. update @stwd/sdk");
      }
      const result = await ctx.signInWithOAuth(provider, tenantId ? { tenantId } : undefined);
      onSuccess?.(result);
    } catch (err) {
      handleError(err);
    }
  };

  const isLoading = step === "loading" || ctx.isLoading;
  const variantClass = variant === "card" ? "stwd-login--card" : "stwd-login--inline";

  if (step === "email-sent") {
    return (
      <div className={`stwd-login ${variantClass} stwd-login--sent ${className ?? ""}`}>
        <div className="stwd-login__notice">
          <p>
            link sent to <strong>{email}</strong>
          </p>
          <p className="stwd-login__notice-sub">check your inbox, then tap the link</p>
        </div>
        <button
          className="stwd-login__btn stwd-login__btn--back"
          onClick={() => {
            setStep("idle");
            setLoadingBtn(null);
          }}
          type="button"
        >
          back to login
        </button>
      </div>
    );
  }

  return (
    <div className={`stwd-login ${variantClass} ${className ?? ""}`}>
      {/* Header */}
      {(logo || title || subtitle || tenantId) && (
        <div className="stwd-login__header">
          {logo && <div className="stwd-login__logo">{logo}</div>}
          {title && <h2 className="stwd-login__title">{title}</h2>}
          {subtitle && <p className="stwd-login__subtitle">{subtitle}</p>}
          {tenantId &&
            ctx.tenants &&
            (() => {
              const tenant = ctx.tenants.find((t) => t.tenantId === tenantId);
              return tenant ? (
                <p className="stwd-login__tenant-name">signing in to {tenant.tenantName}</p>
              ) : null;
            })()}
        </div>
      )}

      {/* Email input */}
      {(showPasskey || showEmail) && (
        <div className="stwd-login__fields">
          <input
            className="stwd-login__input"
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                if (showPasskey) void handlePasskey();
                else if (showEmail) void handleEmail();
              }
            }}
            disabled={isLoading}
            autoComplete="email webauthn"
            aria-label="email"
          />
        </div>
      )}

      {/* Primary auth buttons */}
      <div className="stwd-login__actions">
        {showPasskey && (
          <button
            className="stwd-login__btn stwd-login__btn--passkey"
            onClick={() => void handlePasskey()}
            disabled={isLoading}
            type="button"
          >
            {loadingBtn === "passkey" ? (
              <span className="stwd-login__spinner" />
            ) : (
              <PasskeyIcon size={18} />
            )}
            <span>passkey</span>
          </button>
        )}

        {showEmail && (
          <button
            className="stwd-login__btn stwd-login__btn--email"
            onClick={() => void handleEmail()}
            disabled={isLoading}
            type="button"
          >
            {loadingBtn === "email" ? (
              <span className="stwd-login__spinner" />
            ) : (
              <EmailIcon size={18} />
            )}
            <span>email me a link</span>
          </button>
        )}
      </div>

      {/* Wallet sign-in. Renders inline panels (Approach A) so consumers reuse
          the existing tested SIWE/SIWS flow. The wagmi / @solana/* peer-dep
          imports stay isolated behind dynamic import. */}
      {hasWallet && (
        <div className="stwd-login__wallets stwd-wallet-root" data-testid="stwd-login-wallets">
          {evmReady &&
            (EVMPanel ? (
              <EVMPanel
                classes={walletClasses}
                onSuccess={handleWalletSuccess}
                onError={handleWalletError}
                label="ethereum"
                signLabel={(name) => (name ? `sign in with ${name}` : "sign in with EVM wallet")}
              />
            ) : (
              <button
                type="button"
                className="stwd-login__btn stwd-login__btn--wallet"
                disabled
                data-testid="stwd-login-wallet-evm-loading"
              >
                <EthereumIcon size={18} />
                <span>loading EVM wallet...</span>
              </button>
            ))}
          {solanaReady &&
            (SolanaPanel ? (
              <SolanaPanel
                classes={walletClasses}
                onSuccess={handleWalletSuccess}
                onError={handleWalletError}
                label="solana"
                signLabel={(name) => (name ? `sign in with ${name}` : "sign in with solana wallet")}
              />
            ) : (
              <button
                type="button"
                className="stwd-login__btn stwd-login__btn--wallet"
                disabled
                data-testid="stwd-login-wallet-sol-loading"
              >
                <span>loading solana wallet...</span>
              </button>
            ))}
        </div>
      )}

      {/* Divider */}
      {hasOAuth && (showPasskey || showEmail || hasWallet) && (
        <div className="stwd-login__divider">
          <span>or</span>
        </div>
      )}

      {/* OAuth buttons. Grid layout when 3+ providers, single column when
          1-2. Each button gets its real provider glyph (no shared icon). */}
      {hasOAuth && (
        <div
          className={
            [googleEnabled, discordEnabled, githubEnabled, twitterEnabled].filter(Boolean).length >=
            3
              ? "stwd-login__oauth stwd-login__oauth--grid"
              : "stwd-login__oauth"
          }
        >
          {googleEnabled && (
            <button
              className="stwd-login__btn stwd-login__btn--google"
              onClick={() => void handleOAuth("google")}
              disabled={isLoading}
              type="button"
            >
              {loadingBtn === "google" ? (
                <span className="stwd-login__spinner stwd-login__spinner--dark" />
              ) : (
                <GoogleIcon size={18} />
              )}
              <span>google</span>
            </button>
          )}

          {discordEnabled && (
            <button
              className="stwd-login__btn stwd-login__btn--discord"
              onClick={() => void handleOAuth("discord")}
              disabled={isLoading}
              type="button"
            >
              {loadingBtn === "discord" ? (
                <span className="stwd-login__spinner" />
              ) : (
                <DiscordIcon size={18} />
              )}
              <span>discord</span>
            </button>
          )}

          {githubEnabled && (
            <button
              className="stwd-login__btn stwd-login__btn--github"
              onClick={() => void handleOAuth("github")}
              disabled={isLoading}
              type="button"
            >
              {loadingBtn === "github" ? (
                <span className="stwd-login__spinner" />
              ) : (
                <GitHubIcon size={18} />
              )}
              <span>github</span>
            </button>
          )}

          {twitterEnabled && (
            <button
              className="stwd-login__btn stwd-login__btn--twitter"
              onClick={() => void handleOAuth("twitter")}
              disabled={isLoading}
              type="button"
            >
              {loadingBtn === "twitter" ? (
                <span className="stwd-login__spinner" />
              ) : (
                <XIcon size={16} />
              )}
              <span>x</span>
            </button>
          )}
        </div>
      )}

      {/* Legacy SIWE placeholder. Prefer `showWallets` instead. Kept for
          backward compatibility with any consumer that was relying on the
          (disabled) placeholder button. */}
      {showSIWE && !hasWallet && (
        <div className="stwd-login__oauth">
          <button
            className="stwd-login__btn stwd-login__btn--siwe"
            disabled={true}
            type="button"
            title="connect a wallet to sign in"
          >
            <EthereumIcon size={18} />
            <span>sign in with ethereum</span>
          </button>
        </div>
      )}

      {/* Error */}
      {step === "error" && errorMsg && (
        <p className="stwd-login__error" role="alert">
          {errorMsg}
        </p>
      )}
    </div>
  );
}
