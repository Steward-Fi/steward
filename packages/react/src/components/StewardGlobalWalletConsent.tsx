import type { GlobalWalletConsentRequest, StewardClient } from "@stwd/sdk";
import { StewardClient as StewardSdkClient } from "@stwd/sdk";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import { useSteward } from "../hooks/useSteward.js";
import type { StewardGlobalWalletConsentProps } from "../types.js";

function browserOrigin(): string | undefined {
  return typeof window === "undefined" ? undefined : window.location.origin;
}

function sessionClient(baseClient: StewardClient, token: string): StewardClient {
  return new StewardSdkClient({
    baseUrl: baseClient.getBaseUrl(),
    bearerToken: token,
  });
}

export function StewardGlobalWalletConsent({
  appId,
  origin,
  redirectUri,
  scopes,
  initialRequest,
  onApproved,
  onError,
  className,
}: StewardGlobalWalletConsentProps) {
  const { client } = useSteward();
  const auth = useAuth();
  const [request, setRequest] = useState<GlobalWalletConsentRequest | null>(initialRequest ?? null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const resolvedOrigin = origin ?? browserOrigin();
  const requestedScopes = useMemo(() => (scopes?.length ? scopes : ["eth_accounts"]), [scopes]);

  const activeClient = useMemo(() => {
    const token = auth.getToken();
    return token ? sessionClient(client, token) : null;
  }, [auth, client]);

  useEffect(() => {
    let cancelled = false;
    if (!activeClient || initialRequest) return;
    setBusy(true);
    setMessage(null);
    activeClient
      .getGlobalWalletConsentRequest({
        appId,
        origin: resolvedOrigin,
        redirectUri,
        scopes: requestedScopes,
      })
      .then((result) => {
        if (!cancelled) setRequest(result);
      })
      .catch((error) => {
        const err = error instanceof Error ? error : new Error(String(error));
        if (!cancelled) {
          setMessage(err.message);
          onError?.(err);
        }
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeClient, appId, initialRequest, onError, redirectUri, requestedScopes, resolvedOrigin]);

  async function approve(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!activeClient) {
      const error = new Error("Sign in before approving global wallet access.");
      setMessage(error.message);
      onError?.(error);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const result = await activeClient.approveGlobalWalletConsent({
        appId,
        origin: resolvedOrigin,
        redirectUri,
        scopes: requestedScopes,
      });
      setRequest((current) =>
        current
          ? { ...current, consent: result.consent, wallet: result.wallet }
          : ({
              app: {
                id: appId.split("/").pop() ?? appId,
                appId,
                tenantId: appId.split("/")[0] ?? "",
                name: appId,
                environment: "production",
                origin: resolvedOrigin ?? "",
                redirectUri: redirectUri ?? null,
              },
              requestedScopes,
              wallet: result.wallet,
              consent: result.consent,
            } satisfies GlobalWalletConsentRequest),
      );
      onApproved?.(result);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      setMessage(err.message);
      onError?.(err);
    } finally {
      setBusy(false);
    }
  }

  if (!auth.isAuthenticated) {
    return (
      <div className={["stwd-global-wallet-consent", className].filter(Boolean).join(" ")}>
        <h3>connect global wallet</h3>
        <p>sign in to approve wallet access</p>
      </div>
    );
  }

  const appName = request?.app.name ?? appId;
  const walletAddress = request?.wallet.address;
  const approved = request?.consent?.status === "active";
  const needsMfa =
    message?.toLowerCase().includes("mfa") || message?.toLowerCase().includes("multi-factor");

  return (
    <form
      className={["stwd-global-wallet-consent", className].filter(Boolean).join(" ")}
      onSubmit={approve}
    >
      <div className="stwd-global-wallet-consent__header">
        <h3>connect global wallet</h3>
        <p>{appName}</p>
      </div>
      {walletAddress && (
        <div className="stwd-global-wallet-consent__wallet">
          <span>wallet</span>
          <code>{walletAddress}</code>
        </div>
      )}
      <div className="stwd-global-wallet-consent__scopes">
        <span>permissions</span>
        <ul>
          {(request?.requestedScopes ?? requestedScopes).map((scope) => (
            <li key={scope}>{scope}</li>
          ))}
        </ul>
      </div>
      {approved && <div className="stwd-global-wallet-consent__success">access approved</div>}
      {message && (
        <div
          className={
            needsMfa ? "stwd-global-wallet-consent__warning" : "stwd-global-wallet-consent__error"
          }
        >
          {message}
        </div>
      )}
      <button type="submit" className="stwd-global-wallet-consent__primary" disabled={busy}>
        {busy ? "approving..." : approved ? "approve again" : "approve"}
      </button>
    </form>
  );
}
