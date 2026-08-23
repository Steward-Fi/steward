import type { UserLinkedAccount } from "@stwd/sdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import { useSteward } from "../hooks/useSteward.js";
import type { StewardLinkedAccountsProps } from "../types.js";
import { truncateAddress } from "../utils/format.js";

type PrimaryLoginMethod = {
  provider: "email" | "wallet";
  providerAccountId: string;
};

const providerLabels: Record<string, string> = {
  discord: "Discord",
  email: "Email",
  ethereum: "Ethereum",
  farcaster: "Farcaster",
  github: "GitHub",
  google: "Google",
  linkedin: "LinkedIn",
  passkey: "Passkey",
  phone: "Phone",
  sms: "SMS",
  solana: "Solana",
  telegram: "Telegram",
  twitter: "X",
  wallet: "Wallet",
  whatsapp: "WhatsApp",
};

function labelProvider(provider: string): string {
  return (
    providerLabels[provider.toLowerCase()] ??
    provider
      .split(/[-_]/g)
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")
  );
}

function displayAccountId(provider: string, accountId: string): string {
  if (/^(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/.test(accountId)) {
    return truncateAddress(accountId, 6);
  }
  if (provider === "passkey" && accountId.length > 24) {
    return `${accountId.slice(0, 10)}...${accountId.slice(-8)}`;
  }
  return accountId;
}

function AccountRow({
  provider,
  accountId,
  expiresAt,
  action,
}: {
  provider: string;
  accountId: string;
  expiresAt?: number | null;
  action?: React.ReactNode;
}) {
  return (
    <div className="stwd-linked-account-row">
      <div className="stwd-linked-account-main">
        <span className="stwd-badge stwd-badge-muted">{labelProvider(provider)}</span>
        <code className="stwd-linked-account-id">{displayAccountId(provider, accountId)}</code>
        {expiresAt ? (
          <span className="stwd-muted-text">
            expires {new Date(expiresAt * 1000).toLocaleDateString()}
          </span>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function StewardLinkedAccounts({
  showPrimaryLoginMethods = true,
  showLinkedAccounts = true,
  showPhoneLinking = true,
  showWalletLinking = true,
  showOAuthLinking = true,
  showSocialLinking = true,
  oauthProviders = ["google", "discord", "github", "twitter"],
  oauthRedirectUri,
  onOAuthLinkRequest,
  ethereumWallet,
  solanaWallet,
  onTelegramLinkRequest,
  onFarcasterLinkRequest,
  allowUnlink = true,
  className,
  onLoaded,
  onUnlink,
  onLink,
  onError,
}: StewardLinkedAccountsProps) {
  const { client } = useSteward();
  const auth = useAuth();
  const [primaryMethods, setPrimaryMethods] = useState<PrimaryLoginMethod[]>([]);
  const [linkedAccounts, setLinkedAccounts] = useState<UserLinkedAccount[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [busyAccount, setBusyAccount] = useState<string | null>(null);
  const [phoneChannel, setPhoneChannel] = useState<"sms" | "whatsapp">("sms");
  const [phone, setPhone] = useState("");
  const [phoneCode, setPhoneCode] = useState("");
  const [phoneOtpSent, setPhoneOtpSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadedAuthEpoch, setLoadedAuthEpoch] = useState<string | null>(null);
  const refreshGeneration = useRef(0);
  const authEpoch = auth.isAuthenticated
    ? JSON.stringify([
        auth.session?.token ?? "",
        auth.user?.id ?? auth.session?.userId ?? "",
        auth.activeTenantId ?? auth.session?.tenantId ?? "",
      ])
    : null;
  const authEpochRef = useRef(authEpoch);
  authEpochRef.current = authEpoch;

  const isCurrentAuthEpoch = useCallback(
    (epoch: string | null): epoch is string => epoch !== null && authEpochRef.current === epoch,
    [],
  );

  const reportError = useCallback(
    (err: unknown) => {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error.message);
      onError?.(error);
    },
    [onError],
  );

  const refresh = useCallback(
    async (epoch = authEpoch) => {
      if (!isCurrentAuthEpoch(epoch)) return;
      const generation = ++refreshGeneration.current;
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.listUserAccounts();
        if (generation !== refreshGeneration.current || !isCurrentAuthEpoch(epoch)) return;
        setPrimaryMethods(result.primaryLoginMethods);
        setLinkedAccounts(result.accounts);
        setLoadedAuthEpoch(epoch);
        onLoaded?.(result);
      } catch (err) {
        if (generation !== refreshGeneration.current || !isCurrentAuthEpoch(epoch)) return;
        reportError(err);
      } finally {
        if (generation === refreshGeneration.current && isCurrentAuthEpoch(epoch)) {
          setIsLoading(false);
        }
      }
    },
    [authEpoch, client, isCurrentAuthEpoch, onLoaded, reportError],
  );

  useEffect(() => {
    refreshGeneration.current += 1;
    setPrimaryMethods([]);
    setLinkedAccounts([]);
    setLoadedAuthEpoch(null);
    setIsLoading(false);
    setBusyAccount(null);
    setError(null);
    setPhoneOtpSent(false);
    if (authEpoch) void refresh(authEpoch);
  }, [authEpoch, refresh]);

  const visiblePrimaryMethods = loadedAuthEpoch === authEpoch ? primaryMethods : [];
  const visibleLinkedAccounts = loadedAuthEpoch === authEpoch ? linkedAccounts : [];

  const unlinkableLinkedAccounts = visibleLinkedAccounts.filter(
    (account) => account.provider !== "cross_app",
  );
  const canUnlink = visiblePrimaryMethods.length + unlinkableLinkedAccounts.length > 1;
  const groupedLinkedAccounts = useMemo(() => {
    return visibleLinkedAccounts.reduce<Record<string, UserLinkedAccount[]>>((acc, account) => {
      const key = labelProvider(account.provider);
      acc[key] ??= [];
      acc[key].push(account);
      return acc;
    }, {});
  }, [visibleLinkedAccounts]);

  async function unlink(account: UserLinkedAccount) {
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    const key = `${account.provider}:${account.providerAccountId}`;
    setBusyAccount(key);
    setError(null);
    try {
      const result = await client.unlinkUserAccount(account.provider, account.providerAccountId);
      if (!isCurrentAuthEpoch(epoch)) return;
      onUnlink?.(account, result);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function sendPhoneOtp(event: React.FormEvent) {
    event.preventDefault();
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount(`phone:${phoneChannel}:send`);
    setError(null);
    try {
      await client.sendUserPhoneAccountLinkOtp(phone.trim(), phoneChannel);
      if (!isCurrentAuthEpoch(epoch)) return;
      setPhoneOtpSent(true);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function verifyPhoneOtp(event: React.FormEvent) {
    event.preventDefault();
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount(`phone:${phoneChannel}:verify`);
    setError(null);
    try {
      const result = await client.verifyUserPhoneAccountLinkOtp(
        { phone: phone.trim(), code: phoneCode.trim() },
        phoneChannel,
      );
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      setPhone("");
      setPhoneCode("");
      setPhoneOtpSent(false);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function linkEthereumWallet() {
    if (!ethereumWallet) return;
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount("wallet:ethereum");
    setError(null);
    try {
      const challenge = await client.createUserEthereumWalletLinkNonce(ethereumWallet.address);
      if (!isCurrentAuthEpoch(epoch)) return;
      const signature = await ethereumWallet.signMessage(challenge.message);
      if (!isCurrentAuthEpoch(epoch)) return;
      const result = await client.linkUserEthereumWallet({
        address: ethereumWallet.address,
        message: challenge.message,
        signature,
      });
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function linkSolanaWallet() {
    if (!solanaWallet) return;
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount("wallet:solana");
    setError(null);
    try {
      const challenge = await client.createUserSolanaWalletLinkNonce(solanaWallet.publicKey);
      if (!isCurrentAuthEpoch(epoch)) return;
      const signature = await solanaWallet.signMessage(challenge.message);
      if (!isCurrentAuthEpoch(epoch)) return;
      const result = await client.linkUserSolanaWallet({
        publicKey: solanaWallet.publicKey,
        message: challenge.message,
        signature,
      });
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function linkOAuthProvider(provider: string) {
    if (!onOAuthLinkRequest) return;
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount(`oauth:${provider}`);
    setError(null);
    try {
      const redirectUri =
        oauthRedirectUri ??
        (typeof window !== "undefined" ? `${window.location.origin}/auth/callback` : "");
      if (!redirectUri) {
        throw new Error("oauthRedirectUri is required outside a browser");
      }
      const challenge = await client.createUserOAuthAccountLinkChallenge(provider, { redirectUri });
      if (!isCurrentAuthEpoch(epoch)) return;
      const input = await onOAuthLinkRequest(provider, challenge);
      if (!input || !isCurrentAuthEpoch(epoch)) return;
      const result = await client.linkUserOAuthAccount(provider, {
        ...input,
        redirectUri: input.redirectUri ?? challenge.redirectUri,
        state: input.state ?? challenge.state,
      });
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function linkTelegram() {
    if (!onTelegramLinkRequest) return;
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount("social:telegram");
    setError(null);
    try {
      const challenge = await client.createUserTelegramAccountLinkChallenge();
      if (!isCurrentAuthEpoch(epoch)) return;
      if (!challenge.challengeId) {
        throw new Error("Telegram link challenge did not include a challenge id");
      }
      const input = await onTelegramLinkRequest(challenge.challengeId);
      if (!input || !isCurrentAuthEpoch(epoch)) return;
      const result = await client.linkUserTelegramAccount({
        ...input,
        challengeId: challenge.challengeId,
      });
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  async function linkFarcaster() {
    if (!onFarcasterLinkRequest) return;
    const epoch = authEpoch;
    if (!isCurrentAuthEpoch(epoch)) return;
    setBusyAccount("social:farcaster");
    setError(null);
    try {
      const challenge = await client.createUserFarcasterAccountLinkNonce();
      if (!isCurrentAuthEpoch(epoch)) return;
      if (!challenge.nonce) {
        throw new Error("Farcaster link challenge did not include a nonce");
      }
      const input = await onFarcasterLinkRequest(challenge.nonce);
      if (!input || !isCurrentAuthEpoch(epoch)) return;
      const result = await client.linkUserFarcasterAccount(input);
      if (!isCurrentAuthEpoch(epoch)) return;
      onLink?.(result.account);
      await refresh(epoch);
    } catch (err) {
      if (isCurrentAuthEpoch(epoch)) reportError(err);
    } finally {
      if (isCurrentAuthEpoch(epoch)) setBusyAccount(null);
    }
  }

  if (!auth.isAuthenticated) {
    return (
      <section className={["stwd-card stwd-linked-accounts", className].filter(Boolean).join(" ")}>
        <h3 className="stwd-heading">linked accounts</h3>
        <p className="stwd-muted-text">Sign in to manage linked accounts.</p>
      </section>
    );
  }

  return (
    <section className={["stwd-card stwd-linked-accounts", className].filter(Boolean).join(" ")}>
      <div className="stwd-linked-accounts-header">
        <div>
          <h3 className="stwd-heading">linked accounts</h3>
          <p className="stwd-muted-text">Review login methods and connected identities.</p>
        </div>
        <button
          type="button"
          className="stwd-btn stwd-btn-secondary stwd-btn-sm"
          disabled={isLoading}
          onClick={() => void refresh()}
        >
          refresh
        </button>
      </div>

      {isLoading && <div className="stwd-loading">Loading linked accounts...</div>}
      {error && <p className="stwd-error-text">{error}</p>}

      {showPrimaryLoginMethods && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">primary login methods</div>
          {visiblePrimaryMethods.length === 0 ? (
            <p className="stwd-muted-text">No primary login methods returned.</p>
          ) : (
            visiblePrimaryMethods.map((method) => (
              <AccountRow
                key={`${method.provider}:${method.providerAccountId}`}
                provider={method.provider}
                accountId={method.providerAccountId}
              />
            ))
          )}
        </div>
      )}

      {showWalletLinking && (ethereumWallet || solanaWallet) && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">link wallet</div>
          <div className="stwd-linked-wallet-actions">
            {ethereumWallet && (
              <button
                type="button"
                className="stwd-btn stwd-btn-secondary"
                disabled={busyAccount !== null}
                onClick={() => void linkEthereumWallet()}
              >
                {busyAccount === "wallet:ethereum" ? "linking..." : "link ethereum"}
              </button>
            )}
            {solanaWallet && (
              <button
                type="button"
                className="stwd-btn stwd-btn-secondary"
                disabled={busyAccount !== null}
                onClick={() => void linkSolanaWallet()}
              >
                {busyAccount === "wallet:solana" ? "linking..." : "link solana"}
              </button>
            )}
          </div>
        </div>
      )}

      {showOAuthLinking && onOAuthLinkRequest && oauthProviders.length > 0 && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">link social login</div>
          <div className="stwd-linked-account-actions">
            {oauthProviders.map((provider) => (
              <button
                key={provider}
                type="button"
                className="stwd-btn stwd-btn-secondary"
                disabled={busyAccount !== null}
                onClick={() => void linkOAuthProvider(provider)}
              >
                {busyAccount === `oauth:${provider}`
                  ? "linking..."
                  : `link ${labelProvider(provider).toLowerCase()}`}
              </button>
            ))}
          </div>
        </div>
      )}

      {showSocialLinking && (onTelegramLinkRequest || onFarcasterLinkRequest) && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">link social proof</div>
          <div className="stwd-linked-account-actions">
            {onTelegramLinkRequest && (
              <button
                type="button"
                className="stwd-btn stwd-btn-secondary"
                disabled={busyAccount !== null}
                onClick={() => void linkTelegram()}
              >
                {busyAccount === "social:telegram" ? "linking..." : "link telegram"}
              </button>
            )}
            {onFarcasterLinkRequest && (
              <button
                type="button"
                className="stwd-btn stwd-btn-secondary"
                disabled={busyAccount !== null}
                onClick={() => void linkFarcaster()}
              >
                {busyAccount === "social:farcaster" ? "linking..." : "link farcaster"}
              </button>
            )}
          </div>
        </div>
      )}

      {showPhoneLinking && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">link phone</div>
          <form className="stwd-linked-account-form" onSubmit={sendPhoneOtp}>
            <select
              className="stwd-select stwd-linked-account-channel"
              value={phoneChannel}
              onChange={(event) => {
                setPhoneChannel(event.currentTarget.value as "sms" | "whatsapp");
                setPhoneOtpSent(false);
                setPhoneCode("");
              }}
            >
              <option value="sms">SMS</option>
              <option value="whatsapp">WhatsApp</option>
            </select>
            <input
              className="stwd-input"
              value={phone}
              onChange={(event) => {
                setPhone(event.currentTarget.value);
                setPhoneOtpSent(false);
              }}
              inputMode="tel"
              autoComplete="tel"
              placeholder="+14155550123"
              required
            />
            <button
              type="submit"
              className="stwd-btn stwd-btn-secondary"
              disabled={!phone.trim() || busyAccount !== null}
            >
              {busyAccount === `phone:${phoneChannel}:send` ? "sending..." : "send code"}
            </button>
          </form>
          {phoneOtpSent && (
            <form className="stwd-linked-account-form" onSubmit={verifyPhoneOtp}>
              <input
                className="stwd-input stwd-linked-account-code"
                value={phoneCode}
                onChange={(event) => setPhoneCode(event.currentTarget.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                required
              />
              <button
                type="submit"
                className="stwd-btn stwd-btn-primary"
                disabled={!phoneCode.trim() || busyAccount !== null}
              >
                {busyAccount === `phone:${phoneChannel}:verify` ? "linking..." : "verify"}
              </button>
            </form>
          )}
        </div>
      )}

      {showLinkedAccounts && (
        <div className="stwd-linked-account-section">
          <div className="stwd-subheading">connected identities</div>
          {visibleLinkedAccounts.length === 0 ? (
            <p className="stwd-muted-text">No linked accounts yet.</p>
          ) : (
            Object.entries(groupedLinkedAccounts).map(([group, accounts]) => (
              <div key={group} className="stwd-linked-account-group">
                <div className="stwd-linked-account-group-title">{group}</div>
                {accounts.map((account) => {
                  const key = `${account.provider}:${account.providerAccountId}`;
                  return (
                    <AccountRow
                      key={account.id}
                      provider={account.provider}
                      accountId={account.providerAccountId}
                      expiresAt={account.expiresAt}
                      action={
                        account.provider === "cross_app" ? (
                          <span className="stwd-muted-text">grant-backed</span>
                        ) : allowUnlink ? (
                          <button
                            type="button"
                            className="stwd-btn stwd-btn-ghost stwd-btn-sm"
                            disabled={!canUnlink || busyAccount === key}
                            onClick={() => void unlink(account)}
                          >
                            {busyAccount === key ? "removing..." : "unlink"}
                          </button>
                        ) : undefined
                      }
                    />
                  );
                })}
              </div>
            ))
          )}
        </div>
      )}
    </section>
  );
}
