import { type FormEvent, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import type { StewardMfaChallengeProps } from "../types.js";

export function StewardMfaChallenge({
  challenge,
  onSuccess,
  onError,
  allowRecoveryCode = true,
  className,
}: StewardMfaChallengeProps) {
  const auth = useAuth();
  const [code, setCode] = useState("");
  const [mode, setMode] = useState<"code" | "recovery">("code");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const trimmed = code.trim();
      const result =
        mode === "recovery"
          ? await auth.completeRecoveryCodeMfa(challenge.challengeId, trimmed)
          : challenge.type === "sms"
            ? await auth.completeSmsMfa(challenge.challengeId, trimmed)
            : await auth.completeTotpMfa(challenge.challengeId, trimmed);
      onSuccess?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setMessage(error.message);
      onError?.(error);
    } finally {
      setBusy(false);
    }
  }

  async function completePasskey() {
    setBusy(true);
    setMessage(null);
    try {
      const result = await auth.completePasskeyMfa();
      onSuccess?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setMessage(error.message);
      onError?.(error);
    } finally {
      setBusy(false);
    }
  }

  if (challenge.type === "passkey") {
    return (
      <div className={["stwd-mfa-challenge", className].filter(Boolean).join(" ")}>
        <div className="stwd-mfa-challenge__header">
          <h3>multi-factor verification</h3>
        </div>
        <button
          type="button"
          className="stwd-mfa-primary"
          disabled={busy}
          onClick={() => void completePasskey()}
        >
          {busy ? "verifying..." : "verify with passkey"}
        </button>
        {message && <div className="stwd-mfa-error">{message}</div>}
      </div>
    );
  }

  const inputMode = mode === "recovery" ? "text" : "numeric";
  const pattern = mode === "recovery" ? undefined : "[0-9]*";
  const label = mode === "recovery" ? "recovery code" : `${challenge.type} code`;

  return (
    <form className={["stwd-mfa-challenge", className].filter(Boolean).join(" ")} onSubmit={submit}>
      <div className="stwd-mfa-challenge__header">
        <h3>multi-factor verification</h3>
      </div>
      <label className="stwd-mfa-field">
        <span>{label}</span>
        <input
          value={code}
          onChange={(event) => setCode(event.currentTarget.value)}
          autoComplete="one-time-code"
          inputMode={inputMode}
          pattern={pattern}
          required
        />
      </label>
      {allowRecoveryCode && challenge.type === "totp" && (
        <button
          type="button"
          className="stwd-mfa-link"
          onClick={() => {
            setCode("");
            setMode((current) => (current === "recovery" ? "code" : "recovery"));
          }}
        >
          {mode === "recovery" ? "use authenticator code" : "use recovery code"}
        </button>
      )}
      {message && <div className="stwd-mfa-error">{message}</div>}
      <button type="submit" className="stwd-mfa-primary" disabled={busy}>
        {busy ? "verifying..." : "verify"}
      </button>
    </form>
  );
}
