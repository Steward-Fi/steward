"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { steward } from "@/lib/api";
import { shortenAddress, formatDate } from "@/lib/utils";
import { EmptyState } from "@/components/empty-state";

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ id: "", name: "" });

  useEffect(() => {
    loadAgents();
  }, []);

  async function loadAgents() {
    try {
      setLoading(true);
      const list = await steward.listAgents();
      setAgents(list);
    } catch (e) {
      console.error("Failed to load agents:", e);
    } finally {
      setLoading(false);
    }
  }

  async function createAgent(e: React.FormEvent) {
    e.preventDefault();
    if (!form.id || !form.name) return;

    try {
      setCreating(true);
      await steward.createWallet(form.id, form.name);
      setShowCreate(false);
      setForm({ id: "", name: "" });
      await loadAgents();
    } catch (e: any) {
      alert(e.message || "Failed to create agent");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
          <p className="text-sm text-zinc-500 mt-1">Manage agent wallets and policies</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="btn btn-primary">
          + New Agent
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={createAgent} className="card p-5 space-y-4">
          <h3 className="text-sm font-medium">Create New Agent</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Agent ID</label>
              <input
                type="text"
                value={form.id}
                onChange={(e) => setForm({ ...form, id: e.target.value })}
                placeholder="my-trading-agent"
                className="w-full bg-[#0a0a0a] border border-[#333] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-600"
              />
            </div>
            <div>
              <label className="text-xs text-zinc-500 block mb-1">Display Name</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Trading Agent #1"
                className="w-full bg-[#0a0a0a] border border-[#333] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-600"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={creating} className="btn btn-primary">
              {creating ? "Creating..." : "Create Agent"}
            </button>
            <button type="button" onClick={() => setShowCreate(false)} className="btn btn-ghost">
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Agent List */}
      {loading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="card p-5 h-20 animate-pulse" />
          ))}
        </div>
      ) : agents.length === 0 ? (
        <EmptyState
          icon="◈"
          title="No agents yet"
          description="Create your first agent to generate a wallet with policy enforcement."
          action={
            <button onClick={() => setShowCreate(true)} className="btn btn-primary">
              Create First Agent
            </button>
          }
        />
      ) : (
        <div className="space-y-2">
          {agents.map((agent) => (
            <Link
              key={agent.id}
              href={`/agents/${agent.id}`}
              className="card p-5 flex items-center justify-between hover:border-zinc-600 transition-colors block"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-lg bg-green-600/10 flex items-center justify-center text-green-400 font-medium text-sm">
                  {agent.name?.charAt(0)?.toUpperCase() || "A"}
                </div>
                <div>
                  <div className="font-medium">{agent.name}</div>
                  <div className="text-xs text-zinc-500 mt-0.5">
                    {agent.id} · {shortenAddress(agent.walletAddress)}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="font-mono text-xs text-zinc-400">{shortenAddress(agent.walletAddress, 6)}</div>
                <div className="text-xs text-zinc-600 mt-0.5">
                  {agent.createdAt ? formatDate(agent.createdAt) : ""}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
