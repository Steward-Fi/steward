"use client";

import { useState } from "react";
import { API_URL, TENANT_ID } from "@/lib/api";

export default function SettingsPage() {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  async function saveWebhook(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await fetch(`${API_URL}/tenants/${TENANT_ID}/webhook`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Tenant": TENANT_ID,
          "X-Steward-Key": process.env.NEXT_PUBLIC_STEWARD_API_KEY || "",
        },
        body: JSON.stringify({ webhookUrl: webhookUrl || undefined }),
      });
      const data = await res.json();
      if (data.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
      }
    } catch (e: any) {
      alert(e.message || "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-zinc-500 mt-1">Tenant configuration</p>
      </div>

      {/* Connection Info */}
      <div className="card p-5 space-y-3">
        <h2 className="text-sm font-medium">Connection</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-zinc-500 block mb-1">API Endpoint</label>
            <div className="bg-[#0a0a0a] border border-[#333] rounded-lg px-3 py-2 text-sm font-mono text-zinc-400">
              {API_URL}
            </div>
          </div>
          <div>
            <label className="text-xs text-zinc-500 block mb-1">Tenant ID</label>
            <div className="bg-[#0a0a0a] border border-[#333] rounded-lg px-3 py-2 text-sm font-mono text-zinc-400">
              {TENANT_ID}
            </div>
          </div>
        </div>
      </div>

      {/* Webhook Config */}
      <form onSubmit={saveWebhook} className="card p-5 space-y-3">
        <h2 className="text-sm font-medium">Webhook Notifications</h2>
        <p className="text-xs text-zinc-500">
          Receive POST requests when transactions need approval or change status.
        </p>
        <div>
          <label className="text-xs text-zinc-500 block mb-1">Webhook URL</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://your-app.com/steward-webhook"
            className="w-full bg-[#0a0a0a] border border-[#333] rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-green-600"
          />
        </div>
        <div className="flex items-center gap-3">
          <button type="submit" disabled={saving} className="btn btn-primary">
            {saving ? "Saving..." : "Save Webhook"}
          </button>
          {saved && <span className="text-xs text-green-400">Saved ✓</span>}
        </div>
      </form>

      {/* SDK Quick Start */}
      <div className="card p-5 space-y-3">
        <h2 className="text-sm font-medium">SDK Quick Start</h2>
        <pre className="bg-[#0a0a0a] border border-[#333] rounded-lg p-4 text-xs text-zinc-300 overflow-x-auto">
{`import { StewardClient } from "@steward/sdk";

const steward = new StewardClient({
  baseUrl: "${API_URL}",
  tenantId: "${TENANT_ID}",
  apiKey: "your-api-key",
});

// Create an agent wallet
const agent = await steward.createWallet("my-agent", "Trading Bot");

// Sign a transaction (policy-checked)
const result = await steward.signTransaction("my-agent", {
  to: "0x...",
  value: "1000000000000000", // 0.001 ETH
  chainId: 8453,
});

// Get policies
const policies = await steward.getPolicies("my-agent");`}
        </pre>
      </div>
    </div>
  );
}
