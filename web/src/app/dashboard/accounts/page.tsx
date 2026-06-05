"use client";

import type {
  DigitalAssetAccount,
  DigitalAssetAccountAggregation,
  DigitalAssetAccountMutationInput,
  DigitalAssetAccountWalletConfiguration,
} from "@stwd/sdk";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import { CopyButton } from "@/components/copy-button";
import { steward } from "@/lib/api";
import { formatDate, shortenAddress } from "@/lib/utils";

type LoadState = "idle" | "loading" | "ready" | "error";
type WalletMode = "existing" | "configured";

type AccountAuditEvent = {
  id: number | string;
  seq: number;
  actor_type: string;
  actor_id?: string | null;
  action: string;
  metadata: Record<string, unknown>;
  request_id?: string | null;
  created_at: string;
};

type AccountFormState = {
  id: string;
  displayName: string;
  metadata: string;
  ownerUserIds: string;
  additionalSignerIds: string;
  signerPolicyIds: string;
  walletMode: WalletMode;
  walletIds: string;
  configuredWallets: string;
};

const emptyForm: AccountFormState = {
  id: "",
  displayName: "",
  metadata: "{}",
  ownerUserIds: "",
  additionalSignerIds: "",
  signerPolicyIds: "",
  walletMode: "existing",
  walletIds: "",
  configuredWallets: "evm, Primary EVM wallet\nsolana, Primary Solana wallet",
};

function accountLabel(account: DigitalAssetAccount): string {
  return account.displayName || account.id;
}

function parseWalletIds(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseOptionalIds(value: string): string[] | undefined {
  const ids = parseWalletIds(value);
  return ids.length > 0 ? ids : undefined;
}

function parseConfiguredWallets(value: string): DigitalAssetAccountWalletConfiguration[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [chainType, name, walletId] = line.split(",").map((part) => part.trim());
      if (chainType !== "evm" && chainType !== "ethereum" && chainType !== "solana") {
        throw new Error('Configured wallet chain must be "evm", "ethereum", or "solana"');
      }
      return {
        chain_type: chainType,
        name: name || undefined,
        wallet_id: walletId || undefined,
      };
    });
}

function parseMetadata(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value || "{}") as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Metadata must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function buildMutationInput(
  form: AccountFormState,
  includeWallets: boolean,
): DigitalAssetAccountMutationInput {
  const input: DigitalAssetAccountMutationInput = {
    display_name: form.displayName.trim() || null,
    metadata: parseMetadata(form.metadata),
  };
  const ownerUserIds = parseOptionalIds(form.ownerUserIds);
  const additionalSignerIds = parseOptionalIds(form.additionalSignerIds);
  const signerPolicyIds = parseOptionalIds(form.signerPolicyIds);
  if (ownerUserIds) input.owner_user_ids = ownerUserIds;
  if (additionalSignerIds) input.additional_signer_ids = additionalSignerIds;
  if (signerPolicyIds) input.signer_policy_ids = signerPolicyIds;
  if (form.id.trim()) input.id = form.id.trim();
  if (!includeWallets) return input;

  if (form.walletMode === "existing") {
    const walletIds = parseWalletIds(form.walletIds);
    if (walletIds.length === 0) throw new Error("Add at least one wallet id");
    input.wallet_ids = walletIds;
    return input;
  }

  const wallets = parseConfiguredWallets(form.configuredWallets);
  if (wallets.length === 0) throw new Error("Add at least one configured wallet");
  input.wallets_configuration = wallets;
  return input;
}

function formForAccount(account: DigitalAssetAccount): AccountFormState {
  return {
    ...emptyForm,
    id: account.id,
    displayName: account.displayName ?? "",
    metadata: JSON.stringify(account.metadata ?? {}, null, 2),
    ownerUserIds: (account.ownerUserIds ?? account.owner_user_ids ?? []).join("\n"),
    additionalSignerIds: (account.additionalSignerIds ?? account.additional_signer_ids ?? []).join(
      "\n",
    ),
    signerPolicyIds: (account.signerPolicyIds ?? account.signer_policy_ids ?? []).join("\n"),
    walletMode: "existing",
    walletIds: account.walletIds.join("\n"),
  };
}

function walletCustodyLabel(wallet: DigitalAssetAccount["wallets"][number]): string {
  const custodyType = wallet.custody?.type ?? wallet.walletType ?? wallet.wallet_type ?? null;
  if (custodyType === "user_embedded") return "User embedded";
  if (custodyType === "server") return "Server custody";
  return custodyType ? custodyType.replaceAll("_", " ") : "Custody unknown";
}

function walletOwnerId(wallet: DigitalAssetAccount["wallets"][number]): string | null {
  return (
    wallet.ownerUserId ??
    wallet.owner_user_id ??
    wallet.custody?.ownerUserId ??
    wallet.custody?.owner_user_id ??
    null
  );
}

function walletSigningSummary(wallet: DigitalAssetAccount["wallets"][number]): string | null {
  if (!wallet.signing) return null;
  const { activeSignerCount, signerCount, activeQuorumCount, quorumCount } = wallet.signing;
  return `${activeSignerCount}/${signerCount} signers, ${activeQuorumCount}/${quorumCount} quorums`;
}

export default function AssetAccountsPage() {
  const [status, setStatus] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [accounts, setAccounts] = useState<DigitalAssetAccount[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState<AccountFormState>(emptyForm);
  const [editForm, setEditForm] = useState<AccountFormState>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [aggregations, setAggregations] = useState<DigitalAssetAccountAggregation[]>([]);
  const [aggregationName, setAggregationName] = useState("");
  const [aggregationSaving, setAggregationSaving] = useState(false);
  const [historyState, setHistoryState] = useState<LoadState>("idle");
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyEvents, setHistoryEvents] = useState<AccountAuditEvent[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);

  const selected = useMemo(
    () => accounts.find((account) => account.id === selectedId) ?? accounts[0] ?? null,
    [accounts, selectedId],
  );

  useEffect(() => {
    void loadAccounts();
  }, []);

  useEffect(() => {
    if (!selected) {
      setEditForm(emptyForm);
      setAggregations([]);
      setHistoryEvents([]);
      setHistoryTotal(0);
      setHistoryState("idle");
      return;
    }
    setSelectedId(selected.id);
    setEditForm(formForAccount(selected));
    void loadAggregations(selected.id);
    void loadAccountHistory(selected.id);
  }, [selected?.id]);

  async function loadAccounts() {
    try {
      setStatus("loading");
      setError(null);
      const result = await steward.accounts.list();
      setAccounts(result.accounts);
      setSelectedId((current) => current ?? result.accounts[0]?.id ?? null);
      setStatus("ready");
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Failed to load asset accounts");
    }
  }

  async function loadAggregations(accountId: string) {
    try {
      const result = await steward.accounts.listAggregations(accountId);
      setAggregations(result.aggregations);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load account aggregations");
    }
  }

  async function loadAccountHistory(accountId: string) {
    try {
      setHistoryState("loading");
      setHistoryError(null);
      const result = await steward.getAuditEvents({
        resourceType: "account",
        resourceId: accountId,
        limit: 10,
      });
      setHistoryEvents(result.data);
      setHistoryTotal(result.pagination.total);
      setHistoryState("ready");
    } catch (err) {
      setHistoryState("error");
      setHistoryError(err instanceof Error ? err.message : "Failed to load account history");
    }
  }

  async function createAccount(event: React.FormEvent) {
    event.preventDefault();
    try {
      setSaving(true);
      setError(null);
      const account = await steward.accounts.create(buildMutationInput(createForm, true));
      setAccounts((current) => [account, ...current.filter((item) => item.id !== account.id)]);
      setSelectedId(account.id);
      setCreateForm(emptyForm);
      setShowCreate(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create asset account");
    } finally {
      setSaving(false);
    }
  }

  async function updateAccount(event: React.FormEvent) {
    event.preventDefault();
    if (!selected) return;
    try {
      setSaving(true);
      setError(null);
      const account = await steward.accounts.update(
        selected.id,
        buildMutationInput(editForm, true),
      );
      setAccounts((current) => current.map((item) => (item.id === account.id ? account : item)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update asset account");
    } finally {
      setSaving(false);
    }
  }

  async function deleteAccount(account: DigitalAssetAccount) {
    if (!window.confirm(`Delete ${accountLabel(account)}?`)) return;
    try {
      setSaving(true);
      setError(null);
      await steward.accounts.delete(account.id);
      setAccounts((current) => current.filter((item) => item.id !== account.id));
      if (selectedId === account.id) setSelectedId(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete asset account");
    } finally {
      setSaving(false);
    }
  }

  async function createAggregation(event: React.FormEvent) {
    event.preventDefault();
    if (!selected) return;
    try {
      setAggregationSaving(true);
      setError(null);
      const aggregation = await steward.accounts.createAggregation(selected.id, {
        display_name: aggregationName.trim() || null,
      });
      setAggregations((current) => [aggregation, ...current]);
      setAggregationName("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create aggregation");
    } finally {
      setAggregationSaving(false);
    }
  }

  async function deleteAggregation(aggregation: DigitalAssetAccountAggregation) {
    if (!selected) return;
    try {
      setAggregationSaving(true);
      setError(null);
      await steward.accounts.deleteAggregation(selected.id, aggregation.id);
      setAggregations((current) => current.filter((item) => item.id !== aggregation.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete aggregation");
    } finally {
      setAggregationSaving(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Asset Accounts</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Group managed wallets into account resources and reusable aggregation snapshots.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowCreate((open) => !open)}
          className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors font-medium"
        >
          New Account
        </button>
      </div>

      <AnimatePresence>
        {showCreate && (
          <AccountForm
            title="Create Asset Account"
            form={createForm}
            onChange={setCreateForm}
            onSubmit={createAccount}
            submitLabel={saving ? "Creating..." : "Create"}
            disabled={saving}
            includeId
          />
        )}
      </AnimatePresence>

      {error && (
        <div className="border border-red-400/20 bg-red-400/5 px-4 py-3 text-sm text-red-300 font-mono">
          {error}
        </div>
      )}

      {status === "loading" ? (
        <div className="space-y-px bg-border">
          {[...Array(3)].map((_, index) => (
            <div key={index} className="bg-bg h-20 animate-pulse" />
          ))}
        </div>
      ) : status === "error" ? (
        <div className="py-16 text-center border border-border-subtle">
          <p className="text-sm text-text-secondary mb-4">Asset accounts could not be loaded.</p>
          <button
            type="button"
            onClick={loadAccounts}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Retry
          </button>
        </div>
      ) : accounts.length === 0 ? (
        <div className="py-20 text-center border border-border-subtle">
          <p className="font-display text-lg font-600 text-text-secondary">No asset accounts yet</p>
          <p className="text-sm text-text-tertiary mt-2 max-w-sm mx-auto">
            Create an account from existing wallet IDs or provision chain-specific wallets.
          </p>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="mt-6 px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Create First Account
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-6">
          <div className="border-t border-border-subtle">
            {accounts.map((account) => {
              const active = selected?.id === account.id;
              return (
                <button
                  key={account.id}
                  type="button"
                  onClick={() => setSelectedId(account.id)}
                  className={`w-full text-left py-5 border-b border-border-subtle px-2 -mx-2 transition-colors ${
                    active ? "bg-bg-elevated" : "hover:bg-bg-elevated/40"
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="font-display font-600 text-sm truncate">
                        {accountLabel(account)}
                      </div>
                      <div className="text-xs text-text-tertiary mt-1 font-mono truncate">
                        {account.id}
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className="text-sm font-mono text-text-secondary">
                        {account.wallets.length}
                      </div>
                      <div className="text-[11px] uppercase tracking-[0.12em] text-text-tertiary">
                        wallets
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {selected && (
            <div className="space-y-6">
              <section className="border border-border bg-bg-elevated p-5 space-y-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="font-display text-lg font-600">{accountLabel(selected)}</h2>
                    <p className="text-xs text-text-tertiary mt-1">
                      Created {formatDate(selected.createdAt)}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void deleteAccount(selected)}
                    disabled={saving}
                    className="px-3 py-1.5 text-xs border border-red-400/30 text-red-300 hover:bg-red-400/10 transition-colors disabled:opacity-40"
                  >
                    Delete
                  </button>
                </div>

                <AccountForm
                  title="Edit Account"
                  form={editForm}
                  onChange={setEditForm}
                  onSubmit={updateAccount}
                  submitLabel={saving ? "Saving..." : "Save Changes"}
                  disabled={saving}
                />
              </section>

              <section className="border border-border bg-bg-elevated p-5 space-y-4">
                <div>
                  <h3 className="font-display text-sm font-600">Authorization Assignments</h3>
                  <p className="text-xs text-text-tertiary mt-1">
                    Account-level owners, additional signers, and policy scopes.
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <AssignmentList
                    label="Owners"
                    values={selected.ownerUserIds ?? selected.owner_user_ids ?? []}
                  />
                  <AssignmentList
                    label="Additional signers"
                    values={selected.additionalSignerIds ?? selected.additional_signer_ids ?? []}
                  />
                  <AssignmentList
                    label="Signer policies"
                    values={selected.signerPolicyIds ?? selected.signer_policy_ids ?? []}
                  />
                </div>
              </section>

              <section className="border border-border bg-bg-elevated p-5 space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <h3 className="font-display text-sm font-600">Wallet Membership</h3>
                  <span className="text-xs text-text-tertiary">
                    {selected.wallets.length} linked
                  </span>
                </div>
                <div className="space-y-3">
                  {selected.wallets.map((wallet) => (
                    <div
                      key={wallet.membershipId}
                      className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_auto] gap-3 border border-border-subtle px-3 py-3"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 min-w-0">
                          <div className="text-sm font-medium truncate">
                            {wallet.name || wallet.id}
                          </div>
                          <span className="text-[11px] uppercase tracking-[0.12em] text-text-tertiary border border-border-subtle px-1.5 py-0.5">
                            {walletCustodyLabel(wallet)}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-tertiary">
                          <span className="font-mono truncate max-w-full">{wallet.id}</span>
                          <span>membership {wallet.membershipId}</span>
                          {wallet.createdAt && <span>created {formatDate(wallet.createdAt)}</span>}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-secondary">
                          {walletSigningSummary(wallet) && (
                            <span>{walletSigningSummary(wallet)}</span>
                          )}
                          {wallet.purpose && <span>purpose {wallet.purpose}</span>}
                          {wallet.venue && <span>venue {wallet.venue}</span>}
                          {walletOwnerId(wallet) && <span>owner {walletOwnerId(wallet)}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 lg:justify-end flex-shrink-0">
                        <span className="text-xs text-text-tertiary">{wallet.chainFamily}</span>
                        {wallet.address && (
                          <>
                            <span className="font-mono text-xs text-text-secondary">
                              {shortenAddress(wallet.address, 6)}
                            </span>
                            <CopyButton text={wallet.address} />
                          </>
                        )}
                        <CopyButton text={wallet.id} />
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="border border-border bg-bg-elevated p-5 space-y-4">
                <div>
                  <h3 className="font-display text-sm font-600">Aggregations</h3>
                  <p className="text-xs text-text-tertiary mt-1">
                    Snapshot this account's wallet IDs and chain families for reporting.
                  </p>
                </div>
                <form onSubmit={createAggregation} className="flex flex-col sm:flex-row gap-3">
                  <input
                    value={aggregationName}
                    onChange={(event) => setAggregationName(event.target.value)}
                    placeholder="Aggregation name"
                    className="flex-1 bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                  />
                  <button
                    type="submit"
                    disabled={aggregationSaving}
                    className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
                  >
                    {aggregationSaving ? "Creating..." : "Create Snapshot"}
                  </button>
                </form>
                <div className="space-y-2">
                  {aggregations.length === 0 ? (
                    <p className="text-sm text-text-tertiary py-4">No aggregation snapshots.</p>
                  ) : (
                    aggregations.map((aggregation) => (
                      <div
                        key={aggregation.id}
                        className="flex items-center justify-between gap-4 border border-border-subtle px-3 py-3"
                      >
                        <div className="min-w-0">
                          <div className="text-sm font-medium truncate">
                            {aggregation.displayName || aggregation.id}
                          </div>
                          <div className="text-xs text-text-tertiary truncate">
                            {aggregation.walletIds.length} wallets -{" "}
                            {aggregation.chainFamilies.join(", ")}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => void deleteAggregation(aggregation)}
                          className="text-xs text-text-tertiary hover:text-red-300 transition-colors"
                        >
                          Remove
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="border border-border bg-bg-elevated p-5 space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="font-display text-sm font-600">Account History</h3>
                    <p className="text-xs text-text-tertiary mt-1">
                      Account-scoped audit events, wallet actions, and adapter lifecycle markers.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void loadAccountHistory(selected.id)}
                    className="text-xs text-text-tertiary hover:text-accent transition-colors"
                  >
                    Refresh
                  </button>
                </div>

                {historyState === "loading" ? (
                  <div className="space-y-2">
                    {[...Array(3)].map((_, index) => (
                      <div
                        key={index}
                        className="h-14 bg-bg animate-pulse border border-border-subtle"
                      />
                    ))}
                  </div>
                ) : historyState === "error" ? (
                  <div className="border border-red-400/20 bg-red-400/5 px-3 py-3 text-xs text-red-300">
                    {historyError}
                  </div>
                ) : historyEvents.length === 0 ? (
                  <p className="text-sm text-text-tertiary py-4">No account history yet.</p>
                ) : (
                  <div className="space-y-2">
                    <div className="text-xs text-text-tertiary">
                      Showing {historyEvents.length} of {historyTotal} events
                    </div>
                    {historyEvents.map((event) => (
                      <AccountHistoryEvent key={`${event.id}-${event.seq}`} event={event} />
                    ))}
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
}

function accountHistoryDetail(event: AccountAuditEvent): string | null {
  const metadata = event.metadata ?? {};
  const details = [
    typeof metadata.status === "string" ? `status ${metadata.status}` : null,
    typeof metadata.walletActionId === "string" ? `action ${metadata.walletActionId}` : null,
    typeof metadata.agentId === "string" ? `wallet ${metadata.agentId}` : null,
    typeof metadata.displayName === "string" ? metadata.displayName : null,
  ].filter(Boolean);
  const adapter = metadata.adapter;
  if (adapter && typeof adapter === "object" && !Array.isArray(adapter)) {
    const adapterRecord = adapter as Record<string, unknown>;
    const adapterDetails = [
      adapterRecord.kind,
      adapterRecord.provider,
      adapterRecord.lifecycleStatus,
    ]
      .filter((value): value is string => typeof value === "string" && value.length > 0)
      .join(" / ");
    if (adapterDetails) details.push(adapterDetails);
  }
  return details.length ? details.join(" - ") : null;
}

function AccountHistoryEvent({ event }: { event: AccountAuditEvent }) {
  const detail = accountHistoryDetail(event);
  return (
    <div className="border border-border-subtle px-3 py-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium text-text truncate">{event.action}</div>
          {detail && <div className="text-xs text-text-secondary mt-1 truncate">{detail}</div>}
        </div>
        <div className="text-xs text-text-tertiary font-mono flex-shrink-0">seq {event.seq}</div>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-text-tertiary">
        <span>{formatDate(event.created_at)}</span>
        <span>{event.actor_type}</span>
        {event.actor_id && <span className="font-mono">{event.actor_id}</span>}
        {event.request_id && <span className="font-mono">request {event.request_id}</span>}
      </div>
    </div>
  );
}

function AssignmentList({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="border border-border-subtle px-3 py-3 min-w-0">
      <div className="text-[11px] uppercase tracking-[0.12em] text-text-tertiary">{label}</div>
      {values.length === 0 ? (
        <div className="mt-2 text-xs text-text-tertiary">None assigned</div>
      ) : (
        <div className="mt-2 space-y-1">
          {values.map((value) => (
            <div key={value} className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-xs text-text-secondary truncate">{value}</span>
              <CopyButton text={value} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AccountForm({
  title,
  form,
  onChange,
  onSubmit,
  submitLabel,
  disabled,
  includeId = false,
}: {
  title: string;
  form: AccountFormState;
  onChange: (form: AccountFormState) => void;
  onSubmit: (event: React.FormEvent) => void;
  submitLabel: string;
  disabled: boolean;
  includeId?: boolean;
}) {
  return (
    <motion.form
      initial={includeId ? { opacity: 0, height: 0 } : false}
      animate={includeId ? { opacity: 1, height: "auto" } : undefined}
      exit={includeId ? { opacity: 0, height: 0 } : undefined}
      transition={{ duration: 0.25, ease: [0.25, 1, 0.5, 1] }}
      onSubmit={onSubmit}
      className={includeId ? "overflow-hidden" : "space-y-4"}
    >
      <div
        className={includeId ? "border border-border bg-bg-elevated p-6 space-y-5" : "space-y-4"}
      >
        <h3 className="font-display text-sm font-600">{title}</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {includeId && (
            <label className="block">
              <span className="text-xs text-text-tertiary block mb-1.5">Account ID</span>
              <input
                value={form.id}
                onChange={(event) => onChange({ ...form, id: event.target.value })}
                placeholder="acct_treasury"
                aria-label={`${title} account id`}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
              />
            </label>
          )}
          <label className="block">
            <span className="text-xs text-text-tertiary block mb-1.5">Display Name</span>
            <input
              value={form.displayName}
              onChange={(event) => onChange({ ...form, displayName: event.target.value })}
              placeholder="Treasury"
              aria-label={`${title} display name`}
              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
            />
          </label>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <label className="block">
            <span className="text-xs text-text-tertiary block mb-1.5">Owner User IDs</span>
            <textarea
              value={form.ownerUserIds}
              onChange={(event) => onChange({ ...form, ownerUserIds: event.target.value })}
              placeholder={"user_123\nuser_456"}
              aria-label={`${title} owner user ids`}
              rows={3}
              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
            />
          </label>
          <label className="block">
            <span className="text-xs text-text-tertiary block mb-1.5">Additional Signer IDs</span>
            <textarea
              value={form.additionalSignerIds}
              onChange={(event) => onChange({ ...form, additionalSignerIds: event.target.value })}
              placeholder={"signer_123\nsigner_456"}
              aria-label={`${title} additional signer ids`}
              rows={3}
              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
            />
          </label>
          <label className="block">
            <span className="text-xs text-text-tertiary block mb-1.5">Signer Policy IDs</span>
            <textarea
              value={form.signerPolicyIds}
              onChange={(event) => onChange({ ...form, signerPolicyIds: event.target.value })}
              placeholder={"policy_tx_review\npolicy_daily_limit"}
              aria-label={`${title} signer policy ids`}
              rows={3}
              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
            />
          </label>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[0.7fr_1.3fr] gap-4">
          <div>
            <label className="text-xs text-text-tertiary block mb-1.5">Wallet Source</label>
            <select
              value={form.walletMode}
              onChange={(event) =>
                onChange({ ...form, walletMode: event.target.value as WalletMode })
              }
              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
              aria-label={`${title} wallet source`}
            >
              <option value="existing">Existing wallet IDs</option>
              <option value="configured">Provision wallets</option>
            </select>
          </div>
          {form.walletMode === "existing" ? (
            <label className="block">
              <span className="text-xs text-text-tertiary block mb-1.5">Wallet IDs</span>
              <textarea
                value={form.walletIds}
                onChange={(event) => onChange({ ...form, walletIds: event.target.value })}
                placeholder={"agent-wallet-1\nagent-wallet-2"}
                aria-label={`${title} wallet ids`}
                rows={3}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
              />
            </label>
          ) : (
            <label className="block">
              <span className="text-xs text-text-tertiary block mb-1.5">Configured Wallets</span>
              <textarea
                value={form.configuredWallets}
                onChange={(event) => onChange({ ...form, configuredWallets: event.target.value })}
                placeholder={"evm, Primary EVM wallet\nsolana, Primary Solana wallet"}
                aria-label={`${title} configured wallets`}
                rows={3}
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
              />
            </label>
          )}
        </div>

        <label className="block">
          <span className="text-xs text-text-tertiary block mb-1.5">Metadata JSON</span>
          <textarea
            value={form.metadata}
            onChange={(event) => onChange({ ...form, metadata: event.target.value })}
            aria-label={`${title} metadata JSON`}
            rows={4}
            className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
          />
        </label>

        <button
          type="submit"
          disabled={disabled}
          className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed font-medium"
        >
          {submitLabel}
        </button>
      </div>
    </motion.form>
  );
}
