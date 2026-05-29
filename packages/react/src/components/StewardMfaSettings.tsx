import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import type { StewardMfaSettingsProps } from "../types.js";

type MfaSnapshot = {
  totpEnabled: boolean;
  totpPending: boolean;
  smsEnabled: boolean;
  smsPending: boolean;
  smsPhone?: string;
  recoveryRemaining: number;
};

export function StewardMfaSettings({
  onRecoveryCodes,
  onError,
  className,
}: StewardMfaSettingsProps) {
  const auth = useAuth();
  const [snapshot, setSnapshot] = useState<MfaSnapshot | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);
  const [totpUri, setTotpUri] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [smsPhone, setSmsPhone] = useState("");
  const [smsCode, setSmsCode] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const reportError = useCallback(
    (err: unknown) => {
      const error = err instanceof Error ? err : new Error(String(err));
      setMessage(error.message);
      onError?.(error);
    },
    [onError],
  );

  const refresh = useCallback(async () => {
    const [totp, sms, recovery] = await Promise.all([
      auth.getTotpStatus(),
      auth.getSmsMfaStatus(),
      auth.getRecoveryCodeStatus(),
    ]);
    setSnapshot({
      totpEnabled: totp.enabled,
      totpPending: totp.pending,
      smsEnabled: sms.enabled,
      smsPending: sms.pending,
      smsPhone: sms.phone,
      recoveryRemaining: recovery.remaining,
    });
  }, [auth]);

  useEffect(() => {
    let cancelled = false;
    setBusy("load");
    refresh()
      .catch((err) => {
        if (!cancelled) reportError(err);
      })
      .finally(() => {
        if (!cancelled) setBusy(null);
      });
    return () => {
      cancelled = true;
    };
  }, [refresh, reportError]);

  async function run(name: string, action: () => Promise<void>) {
    setBusy(name);
    setMessage(null);
    try {
      await action();
      await refresh();
    } catch (err) {
      reportError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className={["stwd-mfa-settings", className].filter(Boolean).join(" ")}>
      <div className="stwd-mfa-settings__header">
        <h3>multi-factor authentication</h3>
        {busy === "load" && <span>loading...</span>}
      </div>

      <div className="stwd-mfa-section">
        <div className="stwd-mfa-section__title">
          <strong>authenticator app</strong>
          <span>
            {snapshot?.totpEnabled ? "enabled" : snapshot?.totpPending ? "pending" : "off"}
          </span>
        </div>
        {!snapshot?.totpEnabled && !totpSecret && (
          <button
            type="button"
            className="stwd-mfa-secondary"
            disabled={busy !== null}
            onClick={() =>
              void run("totp-enroll", async () => {
                const enrollment = await auth.enrollTotp();
                setTotpSecret(enrollment.secret);
                setTotpUri(enrollment.otpauthUri);
              })
            }
          >
            add authenticator
          </button>
        )}
        {totpSecret && (
          <div className="stwd-mfa-enrollment">
            <code>{totpSecret}</code>
            {totpUri && <input readOnly value={totpUri} aria-label="otpauth uri" />}
          </div>
        )}
        {(totpSecret || snapshot?.totpEnabled) && (
          <form
            className="stwd-mfa-inline"
            onSubmit={(event) => {
              event.preventDefault();
              void run(totpSecret ? "totp-verify" : "totp-update", async () => {
                const result = await auth.verifyTotp(totpCode.trim());
                if (result.recoveryCodes?.length) onRecoveryCodes?.(result.recoveryCodes);
                setTotpSecret(null);
                setTotpUri(null);
                setTotpCode("");
              });
            }}
          >
            <input
              value={totpCode}
              onChange={(event) => setTotpCode(event.currentTarget.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              required
            />
            <button type="submit" className="stwd-mfa-primary" disabled={busy !== null}>
              {totpSecret ? "verify" : "check"}
            </button>
          </form>
        )}
        {snapshot?.totpEnabled && (
          <button
            type="button"
            className="stwd-mfa-secondary"
            disabled={busy !== null || !totpCode.trim()}
            onClick={() =>
              void run("totp-unenroll", async () => {
                await auth.unenrollTotp(totpCode.trim());
                setTotpCode("");
              })
            }
          >
            remove authenticator
          </button>
        )}
      </div>

      <div className="stwd-mfa-section">
        <div className="stwd-mfa-section__title">
          <strong>sms</strong>
          <span>
            {snapshot?.smsEnabled
              ? `enabled ${snapshot.smsPhone ?? ""}`
              : snapshot?.smsPending
                ? "pending"
                : "off"}
          </span>
        </div>
        {!snapshot?.smsEnabled && (
          <form
            className="stwd-mfa-inline"
            onSubmit={(event) => {
              event.preventDefault();
              void run("sms-enroll", async () => {
                await auth.enrollSmsMfa(smsPhone.trim());
              });
            }}
          >
            <input
              value={smsPhone}
              onChange={(event) => setSmsPhone(event.currentTarget.value)}
              inputMode="tel"
              autoComplete="tel"
              placeholder="+14155550123"
              required
            />
            <button type="submit" className="stwd-mfa-primary" disabled={busy !== null}>
              add sms
            </button>
          </form>
        )}
        {(snapshot?.smsPending || snapshot?.smsEnabled) && (
          <form
            className="stwd-mfa-inline"
            onSubmit={(event) => {
              event.preventDefault();
              void run(snapshot?.smsPending ? "sms-verify" : "sms-unenroll", async () => {
                if (snapshot?.smsPending) {
                  await auth.verifySmsMfa(smsCode.trim());
                } else {
                  await auth.unenrollSmsMfa(smsCode.trim());
                }
                setSmsCode("");
              });
            }}
          >
            <input
              value={smsCode}
              onChange={(event) => setSmsCode(event.currentTarget.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              required
            />
            <button type="submit" className="stwd-mfa-primary" disabled={busy !== null}>
              {snapshot?.smsPending ? "verify" : "remove sms"}
            </button>
          </form>
        )}
        {snapshot?.smsEnabled && (
          <button
            type="button"
            className="stwd-mfa-secondary"
            disabled={busy !== null}
            onClick={() => void run("sms-send", async () => void auth.sendSmsMfaCode())}
          >
            send sms code
          </button>
        )}
      </div>

      <div className="stwd-mfa-section">
        <div className="stwd-mfa-section__title">
          <strong>recovery codes</strong>
          <span>{snapshot ? `${snapshot.recoveryRemaining} remaining` : "loading"}</span>
        </div>
        {snapshot?.totpEnabled && (
          <button
            type="button"
            className="stwd-mfa-secondary"
            disabled={busy !== null || !totpCode.trim()}
            onClick={() =>
              void run("recovery-regenerate", async () => {
                const result = await auth.regenerateRecoveryCodes(totpCode.trim());
                onRecoveryCodes?.(result.recoveryCodes);
                setTotpCode("");
              })
            }
          >
            regenerate recovery codes
          </button>
        )}
      </div>

      {message && <div className="stwd-mfa-error">{message}</div>}
    </section>
  );
}
