import type { EncryptedUserWalletKeyImportResult } from "@stwd/sdk";
import { type FormEvent, useCallback, useRef, useState } from "react";
import { useAuth } from "../hooks/useAuth.js";
import {
  type UserWalletImportChain,
  useEncryptedUserWalletKeyImport,
} from "../hooks/useEncryptedUserWalletKeyImport.js";
import { truncateAddress } from "../utils/format.js";

export interface StewardUserWalletKeyImportProps {
  chain?: UserWalletImportChain;
  walletIndex?: number;
  allowChainSelection?: boolean;
  className?: string;
  labels?: {
    title?: string;
    chain?: string;
    walletIndex?: string;
    privateKey?: string;
    submit?: string;
    submitting?: string;
    signedOut?: string;
    success?: string;
  };
  onImported?: (result: EncryptedUserWalletKeyImportResult) => void;
  onError?: (error: Error) => void;
}

function normalizeWalletIndex(value: string): number | undefined {
  if (value.trim() === "") return undefined;
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error("walletIndex must be a non-negative integer");
  }
  return index;
}

export function StewardUserWalletKeyImport({
  chain = "evm",
  walletIndex,
  allowChainSelection = true,
  className,
  labels,
  onImported,
  onError,
}: StewardUserWalletKeyImportProps) {
  const auth = useAuth();
  const privateKeyRef = useRef<HTMLTextAreaElement | null>(null);
  const [selectedChain, setSelectedChain] = useState<UserWalletImportChain>(chain);
  const [walletIndexValue, setWalletIndexValue] = useState(
    walletIndex === undefined ? "" : String(walletIndex),
  );
  const [localError, setLocalError] = useState<string | null>(null);
  const { importKey, isImporting, error, result } = useEncryptedUserWalletKeyImport();

  const reportError = useCallback(
    (err: unknown) => {
      const nextError = err instanceof Error ? err : new Error(String(err));
      setLocalError(nextError.message);
      onError?.(nextError);
    },
    [onError],
  );

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!auth.isAuthenticated || isImporting) return;

      const privateKey = privateKeyRef.current?.value.trim() ?? "";
      if (!privateKey) {
        reportError(new Error("private key is required"));
        return;
      }

      setLocalError(null);
      try {
        const imported = await importKey({
          chain: selectedChain,
          walletIndex: normalizeWalletIndex(walletIndexValue),
          privateKey,
        });
        if (privateKeyRef.current) privateKeyRef.current.value = "";
        onImported?.(imported);
      } catch (err) {
        reportError(err);
      }
    },
    [
      auth.isAuthenticated,
      importKey,
      isImporting,
      onImported,
      reportError,
      selectedChain,
      walletIndexValue,
    ],
  );

  const disabled = !auth.isAuthenticated || isImporting;
  const errorMessage = localError ?? error?.message ?? null;
  const successLabel = labels?.success ?? "wallet imported";

  return (
    <form
      className={["stwd-user-wallet-key-import", className].filter(Boolean).join(" ")}
      data-testid="stwd-user-wallet-key-import"
      onSubmit={(event) => void handleSubmit(event)}
    >
      <div className="stwd-user-wallet-key-import__header">
        <h3>{labels?.title ?? "import private key"}</h3>
      </div>

      <div className="stwd-user-wallet-key-import__grid">
        {allowChainSelection ? (
          <label className="stwd-user-wallet-key-import__field">
            <span>{labels?.chain ?? "chain"}</span>
            <select
              className="stwd-select"
              value={selectedChain}
              disabled={isImporting}
              onChange={(event) =>
                setSelectedChain(event.currentTarget.value as UserWalletImportChain)
              }
            >
              <option value="evm">evm</option>
              <option value="solana">solana</option>
            </select>
          </label>
        ) : null}

        <label className="stwd-user-wallet-key-import__field">
          <span>{labels?.walletIndex ?? "wallet index"}</span>
          <input
            className="stwd-input"
            inputMode="numeric"
            min={0}
            type="number"
            value={walletIndexValue}
            disabled={isImporting}
            placeholder="0"
            onChange={(event) => setWalletIndexValue(event.currentTarget.value)}
          />
        </label>
      </div>

      <label className="stwd-user-wallet-key-import__field">
        <span>{labels?.privateKey ?? "private key"}</span>
        <textarea
          ref={privateKeyRef}
          className="stwd-input stwd-user-wallet-key-import__secret"
          autoCapitalize="off"
          autoComplete="off"
          autoCorrect="off"
          disabled={disabled}
          spellCheck={false}
          rows={4}
        />
      </label>

      {result ? (
        <div
          className="stwd-user-wallet-key-import__success"
          data-testid="stwd-user-wallet-key-import-success"
        >
          <span>{successLabel}</span>
          <code>{truncateAddress(result.walletAddress)}</code>
        </div>
      ) : null}

      {errorMessage ? (
        <div
          className="stwd-user-wallet-key-import__error"
          data-testid="stwd-user-wallet-key-import-error"
          role="alert"
        >
          {errorMessage}
        </div>
      ) : null}

      <button type="submit" className="stwd-user-wallet-key-import__primary" disabled={disabled}>
        {!auth.isAuthenticated
          ? (labels?.signedOut ?? "sign in to import")
          : isImporting
            ? (labels?.submitting ?? "importing")
            : (labels?.submit ?? "import key")}
      </button>
    </form>
  );
}
