"use client";

import { useAuth } from "@stwd/react";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { CopyButton } from "@/components/copy-button";
import { API_URL } from "@/lib/api";
import { formatDate } from "@/lib/utils";

type TenantUser = {
  userId: string;
  tenantId: string;
  role: string;
  joinedAt: string;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  tenantCustomMetadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

type LoadState = "idle" | "loading" | "ready" | "error";
const TENANT_ROLES = ["owner", "admin", "developer", "billing", "viewer", "member"] as const;
type TenantRole = (typeof TENANT_ROLES)[number];

function jsonPreview(value: Record<string, unknown>): string {
  const keys = Object.keys(value ?? {});
  if (keys.length === 0) return "{}";
  return JSON.stringify(value);
}

function userLabel(user: Pick<TenantUser, "email" | "name" | "userId">): string {
  return user.email || user.name || user.userId;
}

async function userRequest<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.headers ?? {}),
    },
  });
  const body = (await response.json()) as { ok: boolean; data?: T; error?: string };
  if (!response.ok || !body.ok) {
    throw new Error(body.error || `Request failed with ${response.status}`);
  }
  return body.data as T;
}

export default function UsersPage() {
  const auth = useAuth();
  const [tenantId, setTenantId] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<TenantUser[]>([]);
  const [selected, setSelected] = useState<TenantUser | null>(null);
  const [roleSaving, setRoleSaving] = useState(false);

  useEffect(() => {
    setTenantId((current) => current || auth.activeTenantId || auth.session?.tenantId || "");
  }, [auth.activeTenantId, auth.session?.tenantId]);

  async function loadTenantUsers(e?: React.FormEvent) {
    e?.preventDefault();
    const token = auth.getToken();
    if (!tenantId || !token) return;
    try {
      setStatus("loading");
      setError(null);
      const params = new URLSearchParams();
      if (query.trim()) params.set(query.includes("@") ? "email" : "q", query.trim());
      params.set("limit", "50");
      const data = await userRequest<{ users: TenantUser[] }>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users?${params.toString()}`,
        token,
      );
      setUsers(data.users);
      setSelected((current) =>
        current ? (data.users.find((user) => user.userId === current.userId) ?? null) : null,
      );
      setStatus("ready");
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Failed to load users");
    }
  }

  async function loadTenantUser(userId: string) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    try {
      setError(null);
      const user = await userRequest<TenantUser>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}`,
        token,
      );
      setSelected(user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load user");
    }
  }

  async function updateTenantUserRole(userId: string, role: TenantRole) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    try {
      setRoleSaving(true);
      setError(null);
      const updated = await userRequest<TenantUser>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/role`,
        token,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role }),
        },
      );
      setUsers((current) =>
        current.map((user) => (user.userId === userId ? { ...user, role: updated.role } : user)),
      );
      setSelected((current) =>
        current?.userId === userId ? { ...current, role: updated.role } : current,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update role");
    } finally {
      setRoleSaving(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div>
        <h1 className="font-display text-2xl font-700 tracking-tight">Users</h1>
        <p className="text-sm text-text-tertiary mt-1">Tenant users and metadata</p>
      </div>

      <section className="border border-border-subtle bg-bg">
        <form
          onSubmit={loadTenantUsers}
          className="grid grid-cols-1 gap-3 border-b border-border-subtle p-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
        >
          <div>
            <label className="text-xs text-text-tertiary block mb-1.5">Tenant</label>
            <input
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="tenant-id"
              className="w-full bg-bg-elevated border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-text-tertiary block mb-1.5">Search</label>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="email, name, or user id"
              className="w-full bg-bg-elevated border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={!tenantId || !auth.getToken() || status === "loading"}
              className="h-9 w-full md:w-28 bg-accent text-bg text-sm font-medium hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {status === "loading" ? "Loading" : "Search"}
            </button>
          </div>
        </form>

        {error && (
          <div className="border-b border-border-subtle bg-red-400/5 px-4 py-3 text-xs font-mono text-red-300">
            {error}
          </div>
        )}

        <div className="divide-y divide-border-subtle">
          {status === "idle" ? (
            <div className="p-8 text-sm text-text-tertiary">
              Search requires an owner or admin session for the selected tenant.
            </div>
          ) : status === "loading" ? (
            [...Array(4)].map((_, index) => (
              <div key={index} className="h-16 animate-pulse bg-bg-elevated/40" />
            ))
          ) : users.length === 0 ? (
            <div className="p-8 text-sm text-text-tertiary">No users found.</div>
          ) : (
            users.map((user) => (
              <button
                key={user.userId}
                type="button"
                onClick={() => loadTenantUser(user.userId)}
                className="grid w-full grid-cols-1 gap-3 px-4 py-4 text-left hover:bg-bg-elevated/40 transition-colors md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_auto]"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-text">{userLabel(user)}</div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="truncate font-mono text-xs text-text-tertiary">
                      {user.userId}
                    </span>
                    <CopyButton text={user.userId} />
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="text-xs text-text-tertiary">Role</div>
                  <div className="mt-1 text-sm text-text-secondary">{user.role}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-xs text-text-tertiary">Joined</div>
                  <div className="mt-1 truncate text-sm text-text-secondary">
                    {formatDate(user.joinedAt)}
                  </div>
                </div>
                <div className="text-xs text-text-tertiary md:text-right">
                  {jsonPreview(user.tenantCustomMetadata)}
                </div>
              </button>
            ))
          )}
        </div>
      </section>

      <section className="border border-border-subtle bg-bg min-h-72">
        <AnimatePresence mode="wait">
          {selected ? (
            <motion.div
              key={selected.userId}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="divide-y divide-border-subtle"
            >
              <div className="p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <h2 className="truncate font-display text-lg font-600 text-text">
                      {userLabel(selected)}
                    </h2>
                    <div className="mt-1 flex items-center gap-2">
                      <span className="truncate font-mono text-xs text-text-tertiary">
                        {selected.userId}
                      </span>
                      <CopyButton text={selected.userId} />
                    </div>
                  </div>
                  <div className="text-left sm:text-right">
                    <div className="text-xs text-text-tertiary">Created</div>
                    <div className="mt-1 text-sm text-text-secondary">
                      {formatDate(selected.createdAt)}
                    </div>
                  </div>
                </div>
                <div className="mt-4 grid grid-cols-1 gap-px bg-border sm:grid-cols-3">
                  <div className="bg-bg p-3">
                    <div className="text-xs text-text-tertiary">Tenant</div>
                    <div className="mt-1 truncate font-mono text-sm text-text-secondary">
                      {selected.tenantId}
                    </div>
                  </div>
                  <div className="bg-bg p-3">
                    <div className="text-xs text-text-tertiary">Role</div>
                    <select
                      aria-label="Tenant role"
                      value={selected.role}
                      disabled={roleSaving}
                      onChange={(event) =>
                        updateTenantUserRole(selected.userId, event.target.value as TenantRole)
                      }
                      className="mt-1 w-full bg-bg-elevated border border-border px-2 py-1.5 text-sm text-text-secondary focus:outline-none focus:border-accent transition-colors disabled:opacity-40"
                    >
                      {TENANT_ROLES.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="bg-bg p-3">
                    <div className="text-xs text-text-tertiary">Email Verified</div>
                    <div className="mt-1 text-sm text-text-secondary">
                      {selected.emailVerified ? "Yes" : "No"}
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-4">
                <h3 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
                  Tenant Metadata
                </h3>
                <pre className="mt-3 max-h-64 overflow-auto border border-border-subtle bg-bg-elevated p-3 text-xs text-text-secondary">
                  {JSON.stringify(selected.tenantCustomMetadata ?? {}, null, 2)}
                </pre>
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex min-h-72 items-center justify-center p-8 text-sm text-text-tertiary"
            >
              Select a user.
            </motion.div>
          )}
        </AnimatePresence>
      </section>
    </motion.div>
  );
}
