"use client";

import type {
  AgentIdentity,
  ConditionSet,
  ConditionSetItem,
  ConditionSetItemInput,
  PolicyRule,
  PolicySimulateResult,
  PolicyTemplate,
} from "@stwd/sdk";
import { AnimatePresence, motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import { steward } from "@/lib/api";
import { formatDate } from "@/lib/utils";

function randomIdempotencyKey(prefix: string): string {
  if (typeof crypto.randomUUID === "function") return `${prefix}:${crypto.randomUUID()}`;
  return `${prefix}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard-local policy shape.
//
// The backend `/policies` endpoints return a `PolicyTemplate` with typed
// `rules: PolicyRule[]` (plus `name`, `description`, `isDefault`). This page
// pre-dates the typed template API and has historically rendered a
// UI-categorized shape ("api_access" / "spend_limit" / etc.) with
// `rules: Record<string, unknown>` and an `assignedAgents: string[]` field
// that the template endpoint doesn't expose.
//
// The JSON editor roundtrips the raw `rules` payload, so values survive the
// cast even when they don't match the nominal type. Leaving this shape in
// place keeps the UI identical while the dashboard migrates off the inline
// client. Flagged for a follow-up: unify this with `PolicyTemplate` and stop
// pretending `rules` is a bag.
// ─────────────────────────────────────────────────────────────────────────────
interface PolicyRecord {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  type: "api_access" | "spend_limit" | "rate_limit" | "transaction";
  rules: Record<string, unknown>;
  assignedAgents: string[];
  createdAt: string;
  updatedAt: string;
}

interface PolicyCreatePayload {
  name: string;
  description?: string;
  type: PolicyRecord["type"];
  rules: Record<string, unknown>;
}

interface PolicySimulatePayload {
  policyId: string;
  agentId: string;
  request: {
    kind?: "proxy" | "transaction";
    method?: string;
    url?: string;
    value?: string;
    data?: string;
  };
}

function fromTemplate(t: PolicyTemplate): PolicyRecord {
  return {
    id: t.id,
    tenantId: t.tenantId,
    name: t.name,
    description: t.description ?? undefined,
    type: "transaction",
    rules: t.rules as unknown as Record<string, unknown>,
    assignedAgents: [],
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  };
}

const ease: [number, number, number, number] = [0.25, 1, 0.5, 1];
const CONDITION_SET_ITEM_PAGE_LIMIT = 5;

interface Toast {
  id: string;
  message: string;
  kind: "success" | "error";
}

const POLICY_TYPES: {
  value: PolicyRecord["type"];
  label: string;
  description: string;
}[] = [
  {
    value: "api_access",
    label: "API Access",
    description: "Control which external APIs agents can call",
  },
  {
    value: "spend_limit",
    label: "Spend Limit",
    description: "Cap daily or per-transaction spend",
  },
  {
    value: "rate_limit",
    label: "Rate Limit",
    description: "Throttle request frequency",
  },
  {
    value: "transaction",
    label: "Transaction",
    description: "Rules for on-chain transactions",
  },
];

const TEMPLATES: Record<
  string,
  {
    name: string;
    description: string;
    type: PolicyRecord["type"];
    rules: Record<string, unknown>;
  }
> = {
  "standard-agent": {
    name: "Standard Agent",
    description: "Balanced limits for general-purpose agents",
    type: "transaction",
    rules: {
      maxValuePerTx: "0.1",
      dailySpendLimit: "1.0",
      allowedChains: [8453],
      requireApprovalAbove: "0.05",
    },
  },
  "trading-agent": {
    name: "Trading Agent",
    description: "Higher limits with DEX-focused access controls",
    type: "spend_limit",
    rules: {
      maxValuePerTx: "1.0",
      dailySpendLimit: "10.0",
      allowedChains: [8453, 1],
      requireApprovalAbove: "0.5",
      allowedContracts: [],
    },
  },
  minimal: {
    name: "Minimal",
    description: "Read-only with no spend capability",
    type: "api_access",
    rules: {
      allowedHosts: [],
      blockAll: false,
      maxValuePerTx: "0",
      dailySpendLimit: "0",
    },
  },
};

function typeColor(type: PolicyRecord["type"]) {
  const map: Record<PolicyRecord["type"], string> = {
    api_access: "text-violet-400 bg-violet-400/10",
    spend_limit: "text-amber-400 bg-amber-400/10",
    rate_limit: "text-blue-400 bg-blue-400/10",
    transaction: "text-emerald-400 bg-emerald-400/10",
  };
  return map[type] || "text-text-tertiary bg-bg-surface";
}

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyRecord[]>([]);
  const [agents, setAgents] = useState<AgentIdentity[]>([]);
  const [conditionSets, setConditionSets] = useState<ConditionSet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Selected policy for detail/edit
  const [selected, setSelected] = useState<PolicyRecord | null>(null);

  // Create flow
  const [showCreate, setShowCreate] = useState(false);
  const [createStep, setCreateStep] = useState<"template" | "edit">("template");
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState<PolicyCreatePayload>({
    name: "",
    description: "",
    type: "transaction",
    rules: {},
  });
  const [rulesJson, setRulesJson] = useState("{}");
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Edit policy
  const [editMode, setEditMode] = useState(false);
  const [editJson, setEditJson] = useState("");
  const [editJsonError, setEditJsonError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Assign agents
  const [showAssign, setShowAssign] = useState(false);
  const [assignSelected, setAssignSelected] = useState<Set<string>>(new Set());
  const [assigning, setAssigning] = useState(false);

  // Simulate
  const [showSimulate, setShowSimulate] = useState(false);
  const [simForm, setSimForm] = useState({
    agentId: "",
    method: "GET",
    url: "",
    value: "",
    data: "",
  });
  const [simResult, setSimResult] = useState<PolicySimulateResult | null>(null);
  const [simulating, setSimulating] = useState(false);

  // Condition sets
  const [conditionSetName, setConditionSetName] = useState("");
  const [conditionSetDescription, setConditionSetDescription] = useState("");
  const [conditionSetItems, setConditionSetItems] = useState("");
  const [conditionSetItemRows, setConditionSetItemRows] = useState<ConditionSetItem[]>([]);
  const [conditionSetItemLimit, setConditionSetItemLimit] = useState(CONDITION_SET_ITEM_PAGE_LIMIT);
  const [conditionSetItemOffset, setConditionSetItemOffset] = useState(0);
  const [conditionSetLoading, setConditionSetLoading] = useState(false);
  const [conditionSetSaving, setConditionSetSaving] = useState(false);
  const [conditionSetError, setConditionSetError] = useState<string | null>(null);
  const [selectedConditionSetId, setSelectedConditionSetId] = useState<string | null>(null);
  const [conditionSetItemValue, setConditionSetItemValue] = useState("");
  const [conditionSetItemLabel, setConditionSetItemLabel] = useState("");
  const [conditionSetItemSaving, setConditionSetItemSaving] = useState(false);
  const [editingConditionSetItemId, setEditingConditionSetItemId] = useState<string | null>(null);
  const [conditionSetItemEditValue, setConditionSetItemEditValue] = useState("");
  const [conditionSetItemEditLabel, setConditionSetItemEditLabel] = useState("");
  const [conditionSetItemMutatingId, setConditionSetItemMutatingId] = useState<string | null>(null);

  // Delete
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  function toast(message: string, kind: Toast["kind"]) {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((p) => [...p, { id, message, kind }]);
    setTimeout(() => setToasts((p) => p.filter((t) => t.id !== id)), 3500);
  }

  async function loadAll() {
    try {
      setLoading(true);
      setError(null);
      const [p, a, conditionSetRows] = await Promise.all([
        steward.listPolicyTemplates(),
        steward.listAgents(),
        steward.listConditionSets(),
      ]);
      setPolicies(p.map(fromTemplate));
      setAgents(a);
      setConditionSets(conditionSetRows);
      if (!selectedConditionSetId && conditionSetRows[0]) {
        void loadConditionSetItems(conditionSetRows[0].id);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, []);

  async function listAllConditionSetItems(conditionSetId: string): Promise<ConditionSetItem[]> {
    const items: ConditionSetItem[] = [];
    const limit = 200;
    let offset = 0;
    for (;;) {
      const page = await steward.listConditionSetItemsPage(conditionSetId, { limit, offset });
      if (offset > 0 && page.offset !== offset) return items;
      items.push(...page.items);
      const pageLimit = page.limit || limit;
      if (page.items.length < pageLimit) return items;
      offset += pageLimit;
    }
  }

  async function loadConditionSetItems(conditionSetId: string, offset = 0) {
    setSelectedConditionSetId(conditionSetId);
    setConditionSetLoading(true);
    setConditionSetError(null);
    setEditingConditionSetItemId(null);
    try {
      const [page, allItems] = await Promise.all([
        steward.listConditionSetItemsPage(conditionSetId, {
          limit: CONDITION_SET_ITEM_PAGE_LIMIT,
          offset,
        }),
        listAllConditionSetItems(conditionSetId),
      ]);
      setConditionSetItemRows(page.items);
      setConditionSetItemLimit(page.limit);
      setConditionSetItemOffset(page.offset);
      setConditionSetItems(allItems.map((item) => item.value).join("\n"));
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to load condition set items");
    } finally {
      setConditionSetLoading(false);
    }
  }

  function conditionSetItemsFromText(): Array<{ value: string }> {
    return Array.from(
      new Set(
        conditionSetItems
          .split(/[\n,]/)
          .map((item) => item.trim())
          .filter(Boolean),
      ),
    ).map((value) => ({ value }));
  }

  function conditionSetItemPayload(value: string, label: string): ConditionSetItemInput {
    return { value: value.trim(), label: label.trim() || undefined };
  }

  async function handleCreateConditionSet(e: React.FormEvent) {
    e.preventDefault();
    if (!conditionSetName.trim()) return;
    setConditionSetSaving(true);
    setConditionSetError(null);
    try {
      const created = await steward.createConditionSet(
        {
          name: conditionSetName.trim(),
          description: conditionSetDescription.trim() || undefined,
          ownerId: "dashboard",
        },
        { idempotencyKey: randomIdempotencyKey("condition-set-create") },
      );
      const items = conditionSetItemsFromText();
      if (items.length > 0) {
        await steward.replaceConditionSetItems(created.id, items, {
          idempotencyKey: randomIdempotencyKey("condition-set-items-create"),
        });
      }
      setConditionSets((rows) => [created, ...rows]);
      setSelectedConditionSetId(created.id);
      setConditionSetName("");
      setConditionSetDescription("");
      await loadConditionSetItems(created.id);
      toast("Condition set created", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to create condition set");
    } finally {
      setConditionSetSaving(false);
    }
  }

  async function handleSaveConditionSetItems() {
    if (!selectedConditionSetId) return;
    setConditionSetSaving(true);
    setConditionSetError(null);
    try {
      const items = await steward.replaceConditionSetItems(
        selectedConditionSetId,
        conditionSetItemsFromText(),
        { idempotencyKey: randomIdempotencyKey("condition-set-items-save") },
      );
      setConditionSetItems(items.map((item: ConditionSetItem) => item.value).join("\n"));
      await loadConditionSetItems(selectedConditionSetId);
      toast("Condition set items saved", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to save condition set items");
    } finally {
      setConditionSetSaving(false);
    }
  }

  async function handleAddConditionSetItem(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedConditionSetId || !conditionSetItemValue.trim()) return;
    setConditionSetItemSaving(true);
    setConditionSetError(null);
    try {
      await steward.upsertConditionSetItem(
        selectedConditionSetId,
        conditionSetItemPayload(conditionSetItemValue, conditionSetItemLabel),
        { idempotencyKey: randomIdempotencyKey("condition-set-item-upsert") },
      );
      setConditionSetItemValue("");
      setConditionSetItemLabel("");
      await loadConditionSetItems(selectedConditionSetId);
      toast("Condition set item added", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to add condition set item");
    } finally {
      setConditionSetItemSaving(false);
    }
  }

  async function handleRefreshConditionSetItem(itemId: string) {
    if (!selectedConditionSetId) return;
    setConditionSetItemMutatingId(itemId);
    setConditionSetError(null);
    try {
      const item = await steward.getConditionSetItem(selectedConditionSetId, itemId);
      setConditionSetItemRows((rows) => rows.map((row) => (row.id === item.id ? item : row)));
      toast("Condition set item refreshed", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to refresh condition set item");
    } finally {
      setConditionSetItemMutatingId(null);
    }
  }

  async function handleUpdateConditionSetItem(itemId: string) {
    if (!selectedConditionSetId || !conditionSetItemEditValue.trim()) return;
    setConditionSetItemMutatingId(itemId);
    setConditionSetError(null);
    try {
      const updated = await steward.updateConditionSetItem(
        selectedConditionSetId,
        itemId,
        conditionSetItemPayload(conditionSetItemEditValue, conditionSetItemEditLabel),
        { idempotencyKey: randomIdempotencyKey("condition-set-item-update") },
      );
      setConditionSetItemRows((rows) => rows.map((row) => (row.id === updated.id ? updated : row)));
      setEditingConditionSetItemId(null);
      setConditionSetItems(
        (await listAllConditionSetItems(selectedConditionSetId))
          .map((item) => item.value)
          .join("\n"),
      );
      toast("Condition set item updated", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to update condition set item");
    } finally {
      setConditionSetItemMutatingId(null);
    }
  }

  async function handleDeleteConditionSetItem(itemId: string) {
    if (!selectedConditionSetId) return;
    setConditionSetItemMutatingId(itemId);
    setConditionSetError(null);
    try {
      await steward.deleteConditionSetItem(selectedConditionSetId, itemId, {
        idempotencyKey: randomIdempotencyKey("condition-set-item-delete"),
      });
      const nextOffset =
        conditionSetItemRows.length === 1 && conditionSetItemOffset > 0
          ? Math.max(0, conditionSetItemOffset - conditionSetItemLimit)
          : conditionSetItemOffset;
      await loadConditionSetItems(selectedConditionSetId, nextOffset);
      toast("Condition set item deleted", "success");
    } catch (e: unknown) {
      setConditionSetError(e instanceof Error ? e.message : "Failed to delete condition set item");
    } finally {
      setConditionSetItemMutatingId(null);
    }
  }

  const openDetail = useCallback((policy: PolicyRecord) => {
    setSelected(policy);
    setEditMode(false);
    setEditJson(JSON.stringify(policy.rules, null, 2));
    setEditJsonError(null);
    setShowSimulate(false);
    setSimResult(null);
    setShowAssign(false);
    setAssignSelected(new Set(policy.assignedAgents || []));
  }, []);

  function selectTemplate(key: string) {
    const tmpl = TEMPLATES[key];
    setSelectedTemplate(key);
    setCreateForm({
      name: tmpl.name,
      description: tmpl.description,
      type: tmpl.type,
      rules: tmpl.rules,
    });
    setRulesJson(JSON.stringify(tmpl.rules, null, 2));
    setCreateStep("edit");
  }

  function validateJson(val: string): Record<string, unknown> | null {
    try {
      return JSON.parse(val);
    } catch {
      return null;
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    const rules = validateJson(rulesJson);
    if (!rules) {
      setRulesError("Invalid JSON");
      return;
    }
    if (!createForm.name) return;
    setCreating(true);
    setCreateError(null);
    try {
      const template = await steward.createPolicyTemplate({
        name: createForm.name,
        description: createForm.description,
        rules: rules as unknown as PolicyRule[],
      });
      const p: PolicyRecord = {
        ...fromTemplate(template),
        type: createForm.type,
        description: createForm.description,
      };
      setPolicies((prev) => [p, ...prev]);
      setShowCreate(false);
      setCreateStep("template");
      setSelectedTemplate(null);
      setCreateForm({
        name: "",
        description: "",
        type: "transaction",
        rules: {},
      });
      setRulesJson("{}");
      toast("Policy created", "success");
    } catch (e: unknown) {
      setCreateError(e instanceof Error ? e.message : "Failed to create policy");
    } finally {
      setCreating(false);
    }
  }

  async function handleSaveEdit() {
    if (!selected) return;
    const rules = validateJson(editJson);
    if (!rules) {
      setEditJsonError("Invalid JSON");
      return;
    }
    setSaving(true);
    try {
      const updated = fromTemplate(
        await steward.updatePolicyTemplate(selected.id, {
          rules: rules as unknown as PolicyRule[],
        }),
      );
      // Preserve dashboard-only fields (type, assignedAgents) that the
      // template endpoint doesn't round-trip.
      const merged: PolicyRecord = {
        ...updated,
        type: selected.type,
        assignedAgents: selected.assignedAgents,
      };
      setPolicies((p) => p.map((x) => (x.id === merged.id ? merged : x)));
      setSelected(merged);
      setEditMode(false);
      toast("Policy saved", "success");
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : "Failed to save policy", "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleAssign() {
    if (!selected) return;
    setAssigning(true);
    try {
      const assignedAgents = Array.from(assignSelected);
      const result = await steward.assignPolicyTemplate(selected.id, assignedAgents);
      const merged: PolicyRecord = {
        ...selected,
        assignedAgents: result.assignedAgents,
      };
      setPolicies((p) => p.map((x) => (x.id === merged.id ? merged : x)));
      setSelected(merged);
      setShowAssign(false);
      toast("Policy assignments updated", "success");
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : "Failed to assign policy", "error");
    } finally {
      setAssigning(false);
    }
  }

  async function handleSimulate(e: React.FormEvent) {
    e.preventDefault();
    if (!selected || !simForm.agentId) return;
    setSimulating(true);
    setSimResult(null);
    try {
      const payload: PolicySimulatePayload = {
        policyId: selected.id,
        agentId: simForm.agentId,
        request: {
          kind: "proxy",
          method: simForm.method || "GET",
          url: simForm.url,
          value: simForm.value || undefined,
          data: simForm.data || undefined,
        },
      };
      const result = await steward.simulatePolicy({
        policyId: payload.policyId,
        agentId: payload.agentId,
        request: {
          to: payload.request.url || "",
          value: payload.request.value || "0",
          data: payload.request.data,
        },
      });
      setSimResult(result);
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : "Simulation failed", "error");
    } finally {
      setSimulating(false);
    }
  }

  async function handleDelete(policyId: string) {
    setDeleting(true);
    try {
      await steward.deletePolicyTemplate(policyId);
      setPolicies((p) => p.filter((x) => x.id !== policyId));
      if (selected?.id === policyId) setSelected(null);
      setConfirmDelete(null);
      toast("Policy deleted", "success");
    } catch (e: unknown) {
      toast(e instanceof Error ? e.message : "Failed to delete policy", "error");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      {/* Toast */}
      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.96 }}
              transition={{ duration: 0.22, ease }}
              className={`px-4 py-3 text-sm font-medium border pointer-events-auto ${
                t.kind === "success"
                  ? "bg-bg-elevated border-emerald-400/30 text-emerald-400"
                  : "bg-bg-elevated border-red-400/30 text-red-400"
              }`}
            >
              {t.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Policies</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Define and assign access control rules for your agents
          </p>
        </div>
        <button
          onClick={() => {
            setShowCreate(!showCreate);
            setCreateStep("template");
          }}
          className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors font-medium"
        >
          New Policy
        </button>
      </div>

      {/* Create flow */}
      <AnimatePresence>
        {showCreate && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25, ease }}
            className="overflow-hidden"
          >
            <div className="border border-border bg-bg-elevated p-6 space-y-6">
              {createStep === "template" ? (
                <>
                  <h3 className="font-display text-sm font-600">Choose a Template</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {Object.entries(TEMPLATES).map(([key, tmpl]) => (
                      <button
                        key={key}
                        onClick={() => selectTemplate(key)}
                        className={`text-left p-4 border transition-colors space-y-1.5 ${
                          selectedTemplate === key
                            ? "border-accent bg-accent-bg"
                            : "border-border hover:border-accent/60 hover:bg-bg-surface"
                        }`}
                      >
                        <div className="font-display text-sm font-600">{tmpl.name}</div>
                        <div className="text-xs text-text-tertiary">{tmpl.description}</div>
                        <span
                          className={`inline-block text-xs px-1.5 py-0.5 rounded-sm mt-1 ${typeColor(tmpl.type)}`}
                        >
                          {tmpl.type.replace("_", " ")}
                        </span>
                      </button>
                    ))}
                    <button
                      onClick={() => {
                        setSelectedTemplate(null);
                        setCreateForm({
                          name: "",
                          description: "",
                          type: "transaction",
                          rules: {},
                        });
                        setRulesJson("{}");
                        setCreateStep("edit");
                      }}
                      className="text-left p-4 border border-border hover:border-accent/60 hover:bg-bg-surface transition-colors space-y-1.5"
                    >
                      <div className="font-display text-sm font-600">Custom</div>
                      <div className="text-xs text-text-tertiary">
                        Start from scratch with your own rules
                      </div>
                    </button>
                  </div>
                  <button
                    onClick={() => {
                      setShowCreate(false);
                      setCreateStep("template");
                    }}
                    className="text-xs text-text-tertiary hover:text-text transition-colors"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <form onSubmit={handleCreate} className="space-y-5">
                  <div className="flex items-center justify-between">
                    <h3 className="font-display text-sm font-600">Configure Policy</h3>
                    <button
                      type="button"
                      onClick={() => setCreateStep("template")}
                      className="text-xs text-text-tertiary hover:text-text transition-colors"
                    >
                      Back to templates
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs text-text-tertiary block mb-1.5">
                        Name <span className="text-accent">*</span>
                      </label>
                      <input
                        type="text"
                        value={createForm.name}
                        onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                        placeholder="My Policy"
                        className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-text-tertiary block mb-1.5">Type</label>
                      <select
                        value={createForm.type}
                        onChange={(e) =>
                          setCreateForm({
                            ...createForm,
                            type: e.target.value as PolicyRecord["type"],
                          })
                        }
                        className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                      >
                        {POLICY_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-text-tertiary block mb-1.5">Description</label>
                    <input
                      type="text"
                      value={createForm.description}
                      onChange={(e) =>
                        setCreateForm({
                          ...createForm,
                          description: e.target.value,
                        })
                      }
                      placeholder="Describe what this policy does..."
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-text-tertiary block mb-1.5">Rules (JSON)</label>
                    <textarea
                      value={rulesJson}
                      onChange={(e) => {
                        setRulesJson(e.target.value);
                        setRulesError(null);
                      }}
                      rows={8}
                      spellCheck={false}
                      className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors font-mono resize-none"
                      style={{ tabSize: 2 }}
                    />
                    <AnimatePresence>
                      {rulesError && (
                        <motion.p
                          initial={{ opacity: 0, y: -4 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0 }}
                          className="text-xs text-red-400 mt-1 font-mono"
                        >
                          {rulesError}
                        </motion.p>
                      )}
                    </AnimatePresence>
                  </div>

                  <AnimatePresence>
                    {createError && (
                      <motion.p
                        initial={{ opacity: 0, y: -4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="text-xs text-red-400 font-mono"
                      >
                        {createError}
                      </motion.p>
                    )}
                  </AnimatePresence>

                  <div className="flex gap-3">
                    <button
                      type="submit"
                      disabled={creating || !createForm.name}
                      className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed font-medium"
                    >
                      {creating ? "Creating..." : "Create Policy"}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setShowCreate(false);
                        setCreateStep("template");
                      }}
                      className="px-4 py-2 text-sm text-text-tertiary hover:text-text transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error */}
      {error && !loading && (
        <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
          <p className="text-text-secondary text-sm mb-1">Failed to load policies</p>
          <p className="text-text-tertiary text-xs mb-4 font-mono">{error}</p>
          <button
            onClick={loadAll}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Condition sets */}
      <section className="border border-border bg-bg-elevated p-6 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
              Condition Sets
            </h2>
            <p className="text-xs text-text-tertiary mt-1 max-w-2xl">
              Maintain reusable allow/block lists for policy rules that reference condition-set IDs.
            </p>
          </div>
          {selectedConditionSetId && (
            <button
              type="button"
              onClick={handleSaveConditionSetItems}
              disabled={conditionSetSaving || conditionSetLoading}
              className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
            >
              {conditionSetSaving ? "Saving..." : "Save Items"}
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[minmax(260px,360px)_minmax(0,1fr)] gap-5">
          <div className="space-y-4">
            <div className="space-y-px bg-border">
              {conditionSets.length === 0 ? (
                <div className="bg-bg p-5 text-sm text-text-tertiary">
                  {loading ? "Loading condition sets..." : "No condition sets yet"}
                </div>
              ) : (
                conditionSets.map((set) => (
                  <button
                    key={set.id}
                    type="button"
                    onClick={() => loadConditionSetItems(set.id)}
                    className={`w-full bg-bg p-4 text-left transition-colors ${
                      selectedConditionSetId === set.id ? "bg-accent-bg" : "hover:bg-bg-surface"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-text-secondary truncate">
                          {set.name}
                        </div>
                        {set.description && (
                          <div className="text-xs text-text-tertiary mt-1 truncate">
                            {set.description}
                          </div>
                        )}
                      </div>
                      <span className="text-[11px] font-mono text-text-tertiary shrink-0">
                        {set.id}
                      </span>
                    </div>
                  </button>
                ))
              )}
            </div>

            <form
              onSubmit={handleCreateConditionSet}
              className="bg-bg border border-border p-4 space-y-3"
            >
              <label className="space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Name</span>
                <input
                  value={conditionSetName}
                  onChange={(event) => setConditionSetName(event.target.value)}
                  placeholder="Approved recipients"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
              <label className="space-y-1.5 block">
                <span className="text-xs text-text-tertiary block">Description</span>
                <input
                  value={conditionSetDescription}
                  onChange={(event) => setConditionSetDescription(event.target.value)}
                  placeholder="Production transfer allowlist"
                  className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                />
              </label>
              <button
                type="submit"
                disabled={conditionSetSaving || !conditionSetName.trim()}
                className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
              >
                {conditionSetSaving ? "Creating..." : "Create Set"}
              </button>
            </form>
          </div>

          <div className="space-y-4 min-w-0">
            <form
              onSubmit={handleAddConditionSetItem}
              className="bg-bg border border-border p-4 space-y-3"
            >
              <div className="flex items-center justify-between gap-3">
                <h3 className="font-display text-sm font-600 text-text-secondary">Item</h3>
                <button
                  type="submit"
                  disabled={
                    !selectedConditionSetId ||
                    conditionSetItemSaving ||
                    !conditionSetItemValue.trim()
                  }
                  className="px-3 py-1.5 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
                >
                  {conditionSetItemSaving ? "Adding..." : "Add Item"}
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_180px] gap-3">
                <label className="space-y-1.5 block">
                  <span className="text-xs text-text-tertiary block">Value</span>
                  <input
                    value={conditionSetItemValue}
                    onChange={(event) => setConditionSetItemValue(event.target.value)}
                    disabled={!selectedConditionSetId}
                    placeholder="0x1111111111111111111111111111111111111111"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono disabled:opacity-50"
                  />
                </label>
                <label className="space-y-1.5 block">
                  <span className="text-xs text-text-tertiary block">Label</span>
                  <input
                    value={conditionSetItemLabel}
                    onChange={(event) => setConditionSetItemLabel(event.target.value)}
                    disabled={!selectedConditionSetId}
                    placeholder="Treasury"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors disabled:opacity-50"
                  />
                </label>
              </div>
            </form>

            <div className="bg-bg border border-border">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
                <div>
                  <h3 className="font-display text-sm font-600 text-text-secondary">Items</h3>
                  <p className="text-xs text-text-tertiary font-mono">
                    Offset {conditionSetItemOffset}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      selectedConditionSetId &&
                      loadConditionSetItems(
                        selectedConditionSetId,
                        Math.max(0, conditionSetItemOffset - conditionSetItemLimit),
                      )
                    }
                    disabled={
                      !selectedConditionSetId || conditionSetLoading || conditionSetItemOffset === 0
                    }
                    className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      selectedConditionSetId &&
                      loadConditionSetItems(
                        selectedConditionSetId,
                        conditionSetItemOffset + conditionSetItemLimit,
                      )
                    }
                    disabled={
                      !selectedConditionSetId ||
                      conditionSetLoading ||
                      conditionSetItemRows.length < conditionSetItemLimit
                    }
                    className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>

              {conditionSetLoading ? (
                <div className="p-4 text-sm text-text-tertiary">Loading items...</div>
              ) : selectedConditionSetId && conditionSetItemRows.length === 0 ? (
                <div className="p-4 text-sm text-text-tertiary">No items on this page</div>
              ) : !selectedConditionSetId ? (
                <div className="p-4 text-sm text-text-tertiary">Select a condition set</div>
              ) : (
                <div className="divide-y divide-border">
                  {conditionSetItemRows.map((item) => {
                    const isEditing = editingConditionSetItemId === item.id;
                    const isMutating = conditionSetItemMutatingId === item.id;
                    return (
                      <div
                        key={item.id}
                        data-testid={`condition-set-item-${item.id}`}
                        className="p-4 space-y-3"
                      >
                        {isEditing ? (
                          <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_180px] gap-3">
                            <label className="space-y-1.5 block">
                              <span className="text-xs text-text-tertiary block">Value</span>
                              <input
                                value={conditionSetItemEditValue}
                                onChange={(event) =>
                                  setConditionSetItemEditValue(event.target.value)
                                }
                                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors font-mono"
                              />
                            </label>
                            <label className="space-y-1.5 block">
                              <span className="text-xs text-text-tertiary block">Label</span>
                              <input
                                value={conditionSetItemEditLabel}
                                onChange={(event) =>
                                  setConditionSetItemEditLabel(event.target.value)
                                }
                                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                              />
                            </label>
                          </div>
                        ) : (
                          <div className="min-w-0">
                            <div className="text-sm font-mono text-text-secondary break-all">
                              {item.value}
                            </div>
                            <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-text-tertiary">
                              {item.label && <span>{item.label}</span>}
                              <span className="font-mono">{item.id}</span>
                            </div>
                          </div>
                        )}

                        <div className="flex flex-wrap gap-2">
                          {isEditing ? (
                            <>
                              <button
                                type="button"
                                onClick={() => handleUpdateConditionSetItem(item.id)}
                                disabled={isMutating || !conditionSetItemEditValue.trim()}
                                className="px-3 py-1.5 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 font-medium"
                              >
                                {isMutating ? "Saving..." : "Save"}
                              </button>
                              <button
                                type="button"
                                onClick={() => setEditingConditionSetItemId(null)}
                                disabled={isMutating}
                                className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <>
                              <button
                                type="button"
                                onClick={() => handleRefreshConditionSetItem(item.id)}
                                disabled={isMutating}
                                className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                              >
                                Refresh
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setEditingConditionSetItemId(item.id);
                                  setConditionSetItemEditValue(item.value);
                                  setConditionSetItemEditLabel(item.label ?? "");
                                }}
                                disabled={isMutating}
                                className="px-3 py-1.5 text-xs border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                              >
                                Edit
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDeleteConditionSetItem(item.id)}
                                disabled={isMutating}
                                className="px-3 py-1.5 text-xs border border-red-400/20 text-red-400 hover:bg-red-400/10 transition-colors disabled:opacity-40"
                              >
                                {isMutating ? "Deleting..." : "Delete"}
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <label className="space-y-1.5 block">
              <span className="text-xs text-text-tertiary block">Bulk replace values</span>
              <textarea
                value={conditionSetItems}
                onChange={(event) => setConditionSetItems(event.target.value)}
                disabled={!selectedConditionSetId || conditionSetLoading}
                rows={8}
                placeholder={
                  "0x1111111111111111111111111111111111111111\n0x2222222222222222222222222222222222222222"
                }
                className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y disabled:opacity-50"
              />
            </label>
            {conditionSetError && (
              <p className="text-xs text-red-400 font-mono">{conditionSetError}</p>
            )}
          </div>
        </div>
      </section>

      {/* Main: list + detail */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Policies list */}
        <div className="lg:col-span-2">
          {loading ? (
            <div className="space-y-px bg-border">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="bg-bg h-16 animate-pulse" />
              ))}
            </div>
          ) : policies.length === 0 && !error ? (
            <div className="py-16 text-center border border-border-subtle">
              <p className="font-display text-base font-600 text-text-secondary">No policies yet</p>
              <p className="text-sm text-text-tertiary mt-1 max-w-xs mx-auto">
                Create policies to control what your agents are allowed to do.
              </p>
              <button
                onClick={() => setShowCreate(true)}
                className="mt-4 px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
              >
                Create First Policy
              </button>
            </div>
          ) : (
            <div className="border-t border-border-subtle">
              <AnimatePresence initial={false}>
                {policies.map((policy) => (
                  <motion.button
                    key={policy.id}
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.25, ease }}
                    onClick={() => openDetail(policy)}
                    className={`w-full text-left flex items-start justify-between py-4 px-3 border-b border-border-subtle transition-colors group ${
                      selected?.id === policy.id ? "bg-accent-bg" : "hover:bg-bg-elevated/40"
                    }`}
                  >
                    <div className="min-w-0">
                      <div
                        className={`font-display font-600 text-sm truncate ${selected?.id === policy.id ? "text-accent" : "group-hover:text-accent transition-colors"}`}
                      >
                        {policy.name}
                      </div>
                      {policy.description && (
                        <div className="text-xs text-text-tertiary mt-0.5 truncate">
                          {policy.description}
                        </div>
                      )}
                      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                        <span className={`text-xs px-1.5 py-0.5 ${typeColor(policy.type)}`}>
                          {policy.type.replace("_", " ")}
                        </span>
                        {policy.assignedAgents?.length > 0 && (
                          <span className="text-xs text-text-tertiary">
                            {policy.assignedAgents.length} agent
                            {policy.assignedAgents.length !== 1 ? "s" : ""}
                          </span>
                        )}
                      </div>
                    </div>
                  </motion.button>
                ))}
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* Detail panel */}
        <div className="lg:col-span-3">
          <AnimatePresence mode="wait">
            {selected ? (
              <motion.div
                key={selected.id}
                initial={{ opacity: 0, x: 12 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                transition={{ duration: 0.25, ease }}
                className="border border-border bg-bg-elevated space-y-6 p-6"
              >
                {/* Header */}
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h2 className="font-display text-lg font-700">{selected.name}</h2>
                      <span className={`text-xs px-1.5 py-0.5 ${typeColor(selected.type)}`}>
                        {selected.type.replace("_", " ")}
                      </span>
                    </div>
                    {selected.description && (
                      <p className="text-sm text-text-tertiary mt-0.5">{selected.description}</p>
                    )}
                  </div>
                  <button
                    onClick={() => setSelected(null)}
                    className="text-text-tertiary hover:text-text transition-colors text-lg leading-none"
                  >
                    &times;
                  </button>
                </div>

                {/* Metadata */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <div className="text-xs text-text-tertiary">Created</div>
                    <div className="text-sm font-mono text-text-secondary">
                      {formatDate(selected.createdAt)}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-xs text-text-tertiary">Assigned Agents</div>
                    <div className="text-sm font-mono text-text-secondary">
                      {(selected.assignedAgents || []).length}
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-2 flex-wrap">
                  <button
                    onClick={() => {
                      setEditMode(!editMode);
                      if (!editMode) setEditJson(JSON.stringify(selected.rules, null, 2));
                    }}
                    className="px-3 py-1.5 text-xs font-medium border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors"
                  >
                    {editMode ? "Cancel Edit" : "Edit Rules"}
                  </button>
                  <button
                    onClick={() => {
                      setShowAssign(!showAssign);
                      setAssignSelected(new Set(selected.assignedAgents || []));
                    }}
                    className="px-3 py-1.5 text-xs font-medium border border-border text-text-secondary hover:border-accent hover:text-accent transition-colors"
                  >
                    Assign Agents
                  </button>
                  <button
                    onClick={() => setShowSimulate(!showSimulate)}
                    className="px-3 py-1.5 text-xs font-medium border border-border text-text-secondary hover:border-violet-400 hover:text-violet-400 transition-colors"
                  >
                    Simulate
                  </button>
                  <button
                    onClick={() => setConfirmDelete(selected.id)}
                    className="px-3 py-1.5 text-xs font-medium border border-red-400/20 text-red-400 hover:bg-red-400/10 transition-colors ml-auto"
                  >
                    Delete
                  </button>
                </div>

                {/* Delete confirm */}
                <AnimatePresence>
                  {confirmDelete === selected.id && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2, ease }}
                      className="overflow-hidden"
                    >
                      <div className="border border-red-400/20 bg-red-400/5 p-4 space-y-3">
                        <p className="text-xs text-red-400 font-medium">
                          Delete "{selected.name}"? Agents using this policy will lose its
                          protections.
                        </p>
                        <div className="flex gap-3">
                          <button
                            onClick={() => handleDelete(selected.id)}
                            disabled={deleting}
                            className="px-4 py-2 text-xs font-medium bg-red-400/20 text-red-400 hover:bg-red-400/30 transition-colors disabled:opacity-40"
                          >
                            {deleting ? "Deleting..." : "Delete Policy"}
                          </button>
                          <button
                            onClick={() => setConfirmDelete(null)}
                            className="px-3 py-2 text-xs text-text-tertiary hover:text-text transition-colors"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* JSON editor */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs text-text-tertiary">Rules</label>
                    {editMode && (
                      <button
                        onClick={handleSaveEdit}
                        disabled={saving}
                        className="text-xs px-3 py-1 bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40"
                      >
                        {saving ? "Saving..." : "Save Changes"}
                      </button>
                    )}
                  </div>
                  <textarea
                    value={editMode ? editJson : JSON.stringify(selected.rules, null, 2)}
                    onChange={(e) => {
                      if (editMode) {
                        setEditJson(e.target.value);
                        setEditJsonError(null);
                      }
                    }}
                    readOnly={!editMode}
                    rows={10}
                    spellCheck={false}
                    className={`w-full border px-3 py-2 text-sm focus:outline-none transition-colors font-mono resize-none text-xs ${
                      editMode
                        ? "bg-bg border-accent/50 text-text focus:border-accent"
                        : "bg-bg border-border-subtle text-text-secondary cursor-default"
                    }`}
                    style={{ tabSize: 2 }}
                  />
                  <AnimatePresence>
                    {editJsonError && (
                      <motion.p
                        initial={{ opacity: 0, y: -4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="text-xs text-red-400 mt-1 font-mono"
                      >
                        {editJsonError}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </div>

                {/* Assign agents */}
                <AnimatePresence>
                  {showAssign && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2, ease }}
                      className="overflow-hidden"
                    >
                      <div className="border border-border bg-bg p-4 space-y-3">
                        <p className="text-xs font-display font-600">Assign to Agents</p>
                        {agents.length === 0 ? (
                          <p className="text-xs text-text-tertiary">No agents available.</p>
                        ) : (
                          <div className="space-y-1.5 max-h-40 overflow-y-auto">
                            {agents.map((a) => (
                              <label
                                key={a.id}
                                className="flex items-center gap-2 cursor-pointer group"
                              >
                                <input
                                  type="checkbox"
                                  checked={assignSelected.has(a.id)}
                                  onChange={(e) => {
                                    const next = new Set(assignSelected);
                                    if (e.target.checked) next.add(a.id);
                                    else next.delete(a.id);
                                    setAssignSelected(next);
                                  }}
                                  className="accent-amber-400"
                                />
                                <span className="text-sm text-text-secondary group-hover:text-text transition-colors">
                                  {a.name}
                                </span>
                                <span className="text-xs text-text-tertiary font-mono">{a.id}</span>
                              </label>
                            ))}
                          </div>
                        )}
                        <div className="flex gap-3">
                          <button
                            onClick={handleAssign}
                            disabled={assigning}
                            className="px-4 py-2 text-xs font-medium bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40"
                          >
                            {assigning ? "Saving..." : "Save Assignments"}
                          </button>
                          <button
                            onClick={() => setShowAssign(false)}
                            className="px-3 py-2 text-xs text-text-tertiary hover:text-text transition-colors"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* Simulate */}
                <AnimatePresence>
                  {showSimulate && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ duration: 0.2, ease }}
                      className="overflow-hidden"
                    >
                      <form
                        onSubmit={handleSimulate}
                        className="border border-violet-400/20 bg-violet-400/5 p-4 space-y-4"
                      >
                        <p className="text-xs text-violet-400 font-display font-600">
                          Policy Simulator
                        </p>
                        <p className="text-xs text-text-tertiary">
                          Test whether a request would be allowed by this policy.
                        </p>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="text-xs text-text-tertiary block mb-1">
                              Agent <span className="text-accent">*</span>
                            </label>
                            <select
                              value={simForm.agentId}
                              onChange={(e) =>
                                setSimForm({
                                  ...simForm,
                                  agentId: e.target.value,
                                })
                              }
                              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-violet-400 transition-colors"
                            >
                              <option value="">Select agent...</option>
                              {agents.map((a) => (
                                <option key={a.id} value={a.id}>
                                  {a.name}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div>
                            <label className="text-xs text-text-tertiary block mb-1">Method</label>
                            <select
                              value={simForm.method}
                              onChange={(e) =>
                                setSimForm({
                                  ...simForm,
                                  method: e.target.value,
                                })
                              }
                              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-violet-400 transition-colors"
                            >
                              {["GET", "POST", "PUT", "DELETE", "PATCH"].map((m) => (
                                <option key={m} value={m}>
                                  {m}
                                </option>
                              ))}
                            </select>
                          </div>
                        </div>

                        <div>
                          <label className="text-xs text-text-tertiary block mb-1">URL</label>
                          <input
                            type="text"
                            value={simForm.url}
                            onChange={(e) => setSimForm({ ...simForm, url: e.target.value })}
                            placeholder="https://api.example.com/v1/chat"
                            className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-violet-400 transition-colors font-mono"
                          />
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="text-xs text-text-tertiary block mb-1">
                              Value (ETH)
                            </label>
                            <input
                              type="text"
                              value={simForm.value}
                              onChange={(e) =>
                                setSimForm({
                                  ...simForm,
                                  value: e.target.value,
                                })
                              }
                              placeholder="0.0"
                              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-violet-400 transition-colors font-mono"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-text-tertiary block mb-1">
                              Calldata
                            </label>
                            <input
                              type="text"
                              value={simForm.data}
                              onChange={(e) => setSimForm({ ...simForm, data: e.target.value })}
                              placeholder="0x..."
                              className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-violet-400 transition-colors font-mono"
                            />
                          </div>
                        </div>

                        <button
                          type="submit"
                          disabled={simulating || !simForm.agentId}
                          className="px-4 py-2 text-xs font-medium bg-violet-400/20 text-violet-400 hover:bg-violet-400/30 transition-colors disabled:opacity-40"
                        >
                          {simulating ? "Simulating..." : "Run Simulation"}
                        </button>

                        {/* Sim result */}
                        <AnimatePresence>
                          {simResult && (
                            <motion.div
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0 }}
                              className={`p-4 border space-y-2 ${
                                simResult.approved
                                  ? "border-emerald-400/30 bg-emerald-400/5"
                                  : "border-red-400/30 bg-red-400/5"
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                <span
                                  className={`text-sm font-display font-700 ${simResult.approved ? "text-emerald-400" : "text-red-400"}`}
                                >
                                  {simResult.approved ? "ALLOWED" : "DENIED"}
                                </span>
                              </div>
                              {simResult.requiresManualApproval && (
                                <p className="text-xs text-text-secondary">
                                  Manual approval would be required.
                                </p>
                              )}
                              {simResult.results.length > 0 && (
                                <div className="flex flex-wrap gap-1.5">
                                  {simResult.results.map((rule, i) => (
                                    <span
                                      key={i}
                                      className="text-xs px-1.5 py-0.5 bg-bg border border-border font-mono text-text-tertiary"
                                    >
                                      {`${rule.type}: ${rule.passed ? "pass" : "fail"}${rule.reason ? ` — ${rule.reason}` : ""}`}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </form>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-40 border border-border-subtle flex items-center justify-center"
              >
                <p className="text-sm text-text-tertiary">Select a policy to view and edit</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}
