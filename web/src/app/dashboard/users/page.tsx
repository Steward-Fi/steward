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
  deactivatedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

type TenantInvitation = {
  id: string;
  tenantId: string;
  email: string;
  role: string;
  status: string;
  invitedByUserId: string | null;
  acceptedByUserId: string | null;
  acceptedAt: string | null;
  revokedAt: string | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

type TenantUserEvent = {
  id: number;
  seq: number;
  action: string;
  actorType: string;
  actorId: string | null;
  createdAt: string;
};

type LoadState = "idle" | "loading" | "ready" | "error";
const TENANT_ROLES = ["owner", "admin", "developer", "billing", "viewer", "member"] as const;
type TenantRole = (typeof TENANT_ROLES)[number];
const INVITE_ROLES = ["admin", "developer", "billing", "viewer", "member"] as const;
type InviteRole = (typeof INVITE_ROLES)[number];

function jsonPreview(value: Record<string, unknown>): string {
  const keys = Object.keys(value ?? {});
  if (keys.length === 0) return "{}";
  return JSON.stringify(value);
}

function userLabel(user: Pick<TenantUser, "email" | "name" | "userId">): string {
  return user.email || user.name || user.userId;
}

function metadataDraft(value: Record<string, unknown>): string {
  return JSON.stringify(value ?? {}, null, 2);
}

function userStatus(user: Pick<TenantUser, "deactivatedAt">): string {
  return user.deactivatedAt ? "Deactivated" : "Active";
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
  const [selectedEvents, setSelectedEvents] = useState<TenantUserEvent[]>([]);
  const [invitations, setInvitations] = useState<TenantInvitation[]>([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<InviteRole>("member");
  const [sendInviteEmail, setSendInviteEmail] = useState(true);
  const [inviteToken, setInviteToken] = useState<string | null>(null);
  const [inviteSaving, setInviteSaving] = useState(false);
  const [roleSaving, setRoleSaving] = useState(false);
  const [metadataText, setMetadataText] = useState("{}");
  const [metadataSaving, setMetadataSaving] = useState(false);
  const [lifecycleSaving, setLifecycleSaving] = useState(false);
  const [removeSaving, setRemoveSaving] = useState(false);
  const [exportSaving, setExportSaving] = useState(false);

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
      const inviteData = await userRequest<{ invitations: TenantInvitation[] }>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/invitations?status=pending&limit=50`,
        token,
      );
      setUsers(data.users);
      setInvitations(inviteData.invitations);
      const refreshedSelected = selected
        ? (data.users.find((user) => user.userId === selected.userId) ?? null)
        : null;
      setSelected(refreshedSelected);
      if (refreshedSelected) setMetadataText(metadataDraft(refreshedSelected.tenantCustomMetadata));
      if (!refreshedSelected) setSelectedEvents([]);
      setStatus("ready");
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Failed to load users");
    }
  }

  async function exportTenantUsers() {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    try {
      setExportSaving(true);
      setError(null);
      const params = new URLSearchParams();
      if (query.trim()) params.set(query.includes("@") ? "email" : "q", query.trim());
      const response = await fetch(
        `${API_URL}/user/me/tenants/${encodeURIComponent(tenantId)}/users/export?${params.toString()}`,
        {
          headers: {
            Accept: "text/csv",
            Authorization: `Bearer ${token}`,
          },
        },
      );
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error || `Export failed with ${response.status}`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${tenantId}-users.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export users");
    } finally {
      setExportSaving(false);
    }
  }

  async function createInvitation(e?: React.FormEvent) {
    e?.preventDefault();
    const token = auth.getToken();
    if (!tenantId || !token || !inviteEmail.trim()) return;
    try {
      setInviteSaving(true);
      setInviteToken(null);
      setError(null);
      const data = await userRequest<{ invitation: TenantInvitation; token: string }>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/invitations`,
        token,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: inviteEmail.trim(),
            role: inviteRole,
            expiresInSeconds: 7 * 24 * 60 * 60,
            sendEmail: sendInviteEmail,
          }),
        },
      );
      setInvitations((current) => [
        data.invitation,
        ...current.filter(
          (invite) =>
            invite.id !== data.invitation.id &&
            invite.email.toLowerCase() !== data.invitation.email.toLowerCase(),
        ),
      ]);
      setInviteToken(data.token);
      setInviteEmail("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create invitation");
    } finally {
      setInviteSaving(false);
    }
  }

  async function revokeInvitation(invitationId: string) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    try {
      setError(null);
      await userRequest<Record<string, never>>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/invitations/${encodeURIComponent(invitationId)}`,
        token,
        { method: "DELETE" },
      );
      setInvitations((current) => current.filter((invite) => invite.id !== invitationId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke invitation");
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
      const eventsData = await userRequest<{ events: TenantUserEvent[] }>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/events?limit=10`,
        token,
      );
      setSelected(user);
      setSelectedEvents(eventsData.events);
      setMetadataText(metadataDraft(user.tenantCustomMetadata));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load user");
    }
  }

  function replaceTenantUser(updated: TenantUser) {
    setUsers((current) => current.map((user) => (user.userId === updated.userId ? updated : user)));
    setSelected((current) => (current?.userId === updated.userId ? updated : current));
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

  async function updateTenantUserMetadata(userId: string) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(metadataText);
    } catch {
      setError("Tenant metadata must be valid JSON");
      return;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      setError("Tenant metadata must be a JSON object");
      return;
    }
    try {
      setMetadataSaving(true);
      setError(null);
      const updated = await userRequest<TenantUser>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/metadata`,
        token,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tenantCustomMetadata: parsed }),
        },
      );
      replaceTenantUser(updated);
      setMetadataText(metadataDraft(updated.tenantCustomMetadata));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update metadata");
    } finally {
      setMetadataSaving(false);
    }
  }

  async function updateTenantUserLifecycle(user: TenantUser) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    const nextDeactivated = !user.deactivatedAt;
    if (
      nextDeactivated &&
      !window.confirm(`Deactivate ${userLabel(user)}? Existing tenant sessions will be revoked.`)
    ) {
      return;
    }
    try {
      setLifecycleSaving(true);
      setError(null);
      const updated = await userRequest<TenantUser>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(user.userId)}/deactivate`,
        token,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ deactivated: nextDeactivated }),
        },
      );
      replaceTenantUser(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update user lifecycle");
    } finally {
      setLifecycleSaving(false);
    }
  }

  async function removeTenantUser(user: TenantUser) {
    const token = auth.getToken();
    if (!tenantId || !token) return;
    if (!window.confirm(`Remove ${userLabel(user)} from this tenant?`)) return;
    try {
      setRemoveSaving(true);
      setError(null);
      await userRequest<Record<string, never>>(
        `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(user.userId)}`,
        token,
        { method: "DELETE" },
      );
      setUsers((current) => current.filter((candidate) => candidate.userId !== user.userId));
      setSelected((current) => (current?.userId === user.userId ? null : current));
      setSelectedEvents([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove user");
    } finally {
      setRemoveSaving(false);
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
            <div className="flex w-full gap-2 md:w-auto">
              <button
                type="submit"
                disabled={!tenantId || !auth.getToken() || status === "loading"}
                className="h-9 flex-1 bg-accent px-4 text-sm font-medium text-bg hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors md:w-28"
              >
                {status === "loading" ? "Loading" : "Search"}
              </button>
              <button
                type="button"
                onClick={exportTenantUsers}
                disabled={!tenantId || !auth.getToken() || exportSaving}
                className="h-9 border border-border px-3 text-sm text-text-secondary hover:border-accent hover:text-accent disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {exportSaving ? "Exporting" : "Export CSV"}
              </button>
            </div>
          </div>
          <label className="flex items-center gap-2 text-xs text-text-tertiary md:col-span-3">
            <input
              type="checkbox"
              checked={sendInviteEmail}
              onChange={(event) => setSendInviteEmail(event.target.checked)}
              className="h-4 w-4 accent-accent"
            />
            Send invitation email
          </label>
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
                className="grid w-full grid-cols-1 gap-3 px-4 py-4 text-left hover:bg-bg-elevated/40 transition-colors md:grid-cols-[minmax(0,1.4fr)_minmax(0,.65fr)_minmax(0,.75fr)_minmax(0,1fr)_auto]"
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
                  <div className="text-xs text-text-tertiary">Status</div>
                  <div
                    className={
                      user.deactivatedAt
                        ? "mt-1 text-sm text-red-300"
                        : "mt-1 text-sm text-text-secondary"
                    }
                  >
                    {userStatus(user)}
                  </div>
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

      <section className="border border-border-subtle bg-bg">
        <form
          onSubmit={createInvitation}
          className="grid grid-cols-1 gap-3 border-b border-border-subtle p-4 md:grid-cols-[minmax(0,1fr)_180px_auto]"
        >
          <div>
            <label className="text-xs text-text-tertiary block mb-1.5">Invite Email</label>
            <input
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="teammate@example.com"
              className="w-full bg-bg-elevated border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
            />
          </div>
          <div>
            <label className="text-xs text-text-tertiary block mb-1.5">Invite Role</label>
            <select
              aria-label="Invite role"
              value={inviteRole}
              onChange={(event) => setInviteRole(event.target.value as InviteRole)}
              className="w-full bg-bg-elevated border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
            >
              {INVITE_ROLES.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={!tenantId || !auth.getToken() || inviteSaving || !inviteEmail.trim()}
              className="h-9 w-full md:w-28 bg-accent text-bg text-sm font-medium hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {inviteSaving ? "Inviting" : "Invite"}
            </button>
          </div>
        </form>

        {inviteToken && (
          <div className="border-b border-border-subtle bg-accent/5 px-4 py-3">
            <div className="text-xs text-text-tertiary">Invitation Token</div>
            <div className="mt-1 flex items-center gap-2">
              <span className="break-all font-mono text-xs text-text-secondary">{inviteToken}</span>
              <CopyButton text={inviteToken} />
            </div>
          </div>
        )}

        <div className="divide-y divide-border-subtle">
          {invitations.length === 0 ? (
            <div className="p-5 text-sm text-text-tertiary">No pending invitations.</div>
          ) : (
            invitations.map((invite) => (
              <div
                key={invite.id}
                className="grid grid-cols-1 gap-3 px-4 py-4 md:grid-cols-[minmax(0,1.4fr)_minmax(0,.7fr)_minmax(0,1fr)_auto]"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-text">{invite.email}</div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="truncate font-mono text-xs text-text-tertiary">
                      {invite.id}
                    </span>
                    <CopyButton text={invite.id} />
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="text-xs text-text-tertiary">Role</div>
                  <div className="mt-1 text-sm text-text-secondary">{invite.role}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-xs text-text-tertiary">Expires</div>
                  <div className="mt-1 truncate text-sm text-text-secondary">
                    {formatDate(invite.expiresAt)}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => revokeInvitation(invite.id)}
                  className="h-8 self-center border border-border px-3 text-xs text-text-secondary hover:border-red-300 hover:text-red-300 transition-colors"
                >
                  Revoke
                </button>
              </div>
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
                  <div className="flex flex-col items-start gap-2 sm:items-end">
                    <div className="flex flex-wrap justify-start gap-2 sm:justify-end">
                      <button
                        type="button"
                        onClick={() => updateTenantUserLifecycle(selected)}
                        disabled={lifecycleSaving}
                        className={
                          selected.deactivatedAt
                            ? "h-8 border border-border px-3 text-xs text-text-secondary hover:border-accent hover:text-accent disabled:opacity-40 transition-colors"
                            : "h-8 border border-border px-3 text-xs text-text-secondary hover:border-red-300 hover:text-red-300 disabled:opacity-40 transition-colors"
                        }
                      >
                        {lifecycleSaving
                          ? "Saving"
                          : selected.deactivatedAt
                            ? "Reactivate User"
                            : "Deactivate User"}
                      </button>
                      <button
                        type="button"
                        onClick={() => removeTenantUser(selected)}
                        disabled={removeSaving}
                        className="h-8 border border-border px-3 text-xs text-text-secondary hover:border-red-300 hover:text-red-300 disabled:opacity-40 transition-colors"
                      >
                        {removeSaving ? "Removing" : "Remove User"}
                      </button>
                    </div>
                    <div className="text-left sm:text-right">
                      <div className="text-xs text-text-tertiary">Created</div>
                      <div className="mt-1 text-sm text-text-secondary">
                        {formatDate(selected.createdAt)}
                      </div>
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
                    <div className="text-xs text-text-tertiary">Status</div>
                    <div
                      className={
                        selected.deactivatedAt
                          ? "mt-1 text-sm text-red-300"
                          : "mt-1 text-sm text-text-secondary"
                      }
                    >
                      {userStatus(selected)}
                    </div>
                    <div className="mt-1 text-xs text-text-tertiary">
                      {selected.deactivatedAt
                        ? `Since ${formatDate(selected.deactivatedAt)}`
                        : selected.emailVerified
                          ? "Email verified"
                          : "Email unverified"}
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <h3 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
                    Tenant Metadata
                  </h3>
                  <button
                    type="button"
                    onClick={() => updateTenantUserMetadata(selected.userId)}
                    disabled={metadataSaving}
                    className="h-8 border border-border px-3 text-xs text-text-secondary hover:border-accent hover:text-accent disabled:opacity-40 transition-colors"
                  >
                    {metadataSaving ? "Saving" : "Save Metadata"}
                  </button>
                </div>
                <textarea
                  aria-label="Tenant metadata JSON"
                  value={metadataText}
                  onChange={(event) => setMetadataText(event.target.value)}
                  spellCheck={false}
                  className="mt-3 min-h-52 w-full resize-y border border-border-subtle bg-bg-elevated p-3 font-mono text-xs text-text-secondary focus:outline-none focus:border-accent transition-colors"
                />
              </div>

              <div className="p-4">
                <h3 className="font-display text-sm font-600 text-text-secondary tracking-wider uppercase">
                  Activity
                </h3>
                <div className="mt-3 divide-y divide-border-subtle border border-border-subtle">
                  {selectedEvents.length === 0 ? (
                    <div className="p-3 text-xs text-text-tertiary">No user activity.</div>
                  ) : (
                    selectedEvents.map((event) => (
                      <div
                        key={`${event.seq}-${event.id}`}
                        className="grid grid-cols-1 gap-2 p-3 md:grid-cols-[minmax(0,1fr)_minmax(0,.8fr)_auto]"
                      >
                        <div className="min-w-0">
                          <div className="truncate font-mono text-xs text-text-secondary">
                            {event.action}
                          </div>
                          <div className="mt-1 truncate text-xs text-text-tertiary">
                            {event.actorType}
                            {event.actorId ? `:${event.actorId}` : ""}
                          </div>
                        </div>
                        <div className="text-xs text-text-tertiary">
                          {formatDate(event.createdAt)}
                        </div>
                        <div className="font-mono text-xs text-text-tertiary">#{event.seq}</div>
                      </div>
                    ))
                  )}
                </div>
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
