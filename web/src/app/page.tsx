export default function Home() {
  return (
    <div className="min-h-screen bg-[#050505]">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/5 bg-[#050505]/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-green-500 flex items-center justify-center text-white font-bold text-xs">S</div>
            <span className="font-semibold text-white tracking-tight">steward</span>
          </div>
          <div className="flex items-center gap-6">
            <a href="#how-it-works" className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors hidden sm:block">How it works</a>
            <a href="#features" className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors hidden sm:block">Features</a>
            <a href="#platforms" className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors hidden sm:block">Platforms</a>
            <a
              href="https://github.com/0xSolace/steward"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-zinc-400 hover:text-white transition-colors"
            >
              GitHub
            </a>
            <a
              href="/dashboard"
              className="text-sm font-medium bg-green-600 hover:bg-green-700 text-white px-4 py-1.5 rounded-lg transition-colors"
            >
              Dashboard →
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-24 px-6 bg-grid">
        <div className="absolute inset-0 bg-gradient-to-b from-green-500/[0.03] via-transparent to-transparent pointer-events-none" />
        <div className="max-w-4xl mx-auto text-center relative">
          <div className="animate-fade-up opacity-0">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-green-500/20 bg-green-500/5 text-green-400 text-xs font-medium mb-8">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
              Built for the Synthesis Hackathon
            </div>
          </div>

          <h1 className="text-5xl sm:text-7xl font-extrabold tracking-tight leading-[1.05] mb-6 animate-fade-up opacity-0 animate-delay-100">
            Agent wallets with
            <br />
            <span className="bg-gradient-to-r from-green-400 to-emerald-300 bg-clip-text text-transparent">
              policy enforcement
            </span>
          </h1>

          <p className="text-lg sm:text-xl text-zinc-400 max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-up opacity-0 animate-delay-200">
            Give your AI agents wallets. Keep the keys safe. Let users set spending rules.
            Open source infrastructure designed to be embedded.
          </p>

          <div className="flex items-center justify-center gap-4 flex-wrap animate-fade-up opacity-0 animate-delay-300">
            <a
              href="https://github.com/0xSolace/steward"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-white text-black font-semibold px-6 py-3 rounded-xl hover:bg-zinc-200 transition-colors text-sm"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              View on GitHub
            </a>
            <a
              href="#how-it-works"
              className="inline-flex items-center gap-1 text-zinc-400 hover:text-white font-medium px-6 py-3 rounded-xl border border-zinc-800 hover:border-zinc-600 transition-colors text-sm"
            >
              How it works ↓
            </a>
          </div>
        </div>
      </section>

      {/* Trust bar */}
      <section className="border-y border-white/5 py-6 px-6">
        <div className="max-w-4xl mx-auto flex items-center justify-center gap-8 sm:gap-16 text-zinc-600 text-xs uppercase tracking-widest font-medium">
          <span>Open Source</span>
          <span className="text-zinc-800">·</span>
          <span>Self-Hostable</span>
          <span className="text-zinc-800">·</span>
          <span>No Token</span>
          <span className="text-zinc-800">·</span>
          <span>MIT License</span>
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">How it works</h2>
            <p className="text-zinc-500 max-w-xl mx-auto">
              Steward sits between your agent and its wallet. Every transaction goes through user-defined policies before a key is ever touched.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                step: "01",
                title: "Agent requests a transaction",
                desc: "Your agent calls the Steward API with a standard sign request. It never sees the private key.",
                color: "text-green-400",
              },
              {
                step: "02",
                title: "Policies evaluate the request",
                desc: "Spending limits, approved addresses, rate limits, time windows. All configurable per agent.",
                color: "text-emerald-400",
              },
              {
                step: "03",
                title: "Sign, queue, or reject",
                desc: "Auto-approve if within thresholds. Queue for human approval if not. Hard reject if rules are violated.",
                color: "text-teal-400",
              },
            ].map((item) => (
              <div key={item.step} className="relative p-6 rounded-2xl border border-white/5 bg-white/[0.01] hover:bg-white/[0.02] transition-colors">
                <div className={`text-xs font-mono ${item.color} mb-3`}>{item.step}</div>
                <h3 className="text-lg font-semibold mb-2">{item.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>

          {/* Flow diagram */}
          <div className="mt-12 code-block glow-green">
            <div className="px-5 py-3 border-b border-white/5 text-xs text-zinc-600 font-mono">
              transaction flow
            </div>
            <pre className="p-5 text-sm leading-relaxed text-zinc-400 overflow-x-auto font-mono">
{`Agent: POST /vault/:agentId/sign { to: "0x...", value: "500000000000000000" }
                    │
                    ▼
            ┌─── Policy Engine ───┐
            │                     │
            │  ✓ spending-limit   │
            │  ✓ approved-addrs   │
            │  ✓ rate-limit       │
            │  ✗ auto-approve     │  ← above threshold
            │                     │
            └─────────┬───────────┘
                      │
                      ▼
             Queued for approval
                      │
              User approves via
              dashboard / webhook
                      │
                      ▼
          Vault decrypts → signs → broadcasts
                      │
                      ▼
            Agent receives tx hash
            Key re-encrypted, never exposed`}
            </pre>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 px-6 border-t border-white/5">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Built for agent infrastructure</h2>
            <p className="text-zinc-500 max-w-xl mx-auto">
              Everything a platform needs to give agents wallets without giving them keys.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {[
              {
                title: "Encrypted Vault",
                desc: "AES-256-GCM + scrypt key derivation. Private keys are encrypted at rest and only decrypted in memory for the instant of signing.",
                icon: "🔐",
              },
              {
                title: "5 Policy Types",
                desc: "Spending limits (per-tx, daily, weekly). Approved addresses. Auto-approve thresholds. Time windows. Rate limits. Composable.",
                icon: "📋",
              },
              {
                title: "Multi-Tenant",
                desc: "One Steward instance, many platforms. Each tenant gets isolated namespacing, API keys, webhook URLs, and default policies.",
                icon: "🏗️",
              },
              {
                title: "Approval Queue",
                desc: "Transactions that exceed soft thresholds get queued for human review. Approve or reject via dashboard, API, or webhook callback.",
                icon: "⏳",
              },
              {
                title: "Webhook Events",
                desc: "Real-time POST notifications for approval_required, tx_signed, tx_confirmed, tx_failed. Integrate with your own notification flow.",
                icon: "🔔",
              },
              {
                title: "SDK",
                desc: "One import, three core methods. TypeScript. createWallet, signTransaction, getPolicies. Drop it into any agent framework.",
                icon: "📦",
              },
            ].map((f) => (
              <div key={f.title} className="flex gap-4 p-5 rounded-xl border border-white/5 bg-white/[0.01]">
                <div className="text-2xl flex-shrink-0 mt-0.5">{f.icon}</div>
                <div>
                  <h3 className="font-semibold mb-1">{f.title}</h3>
                  <p className="text-sm text-zinc-500 leading-relaxed">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* SDK Code */}
      <section className="py-24 px-6 border-t border-white/5">
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
                Three lines to get started
              </h2>
              <p className="text-zinc-400 leading-relaxed mb-6">
                The SDK is a thin HTTP client. No complex setup, no ceremony. Initialize with your API endpoint and tenant credentials, then call methods.
              </p>
              <ul className="space-y-3 text-sm text-zinc-500">
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5">✓</span>
                  <span>TypeScript with full type inference</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5">✓</span>
                  <span>Works in Node.js, Bun, Deno, edge runtimes</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5">✓</span>
                  <span>Policy violations return structured results</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-0.5">✓</span>
                  <span>Zero dependencies beyond fetch</span>
                </li>
              </ul>
            </div>

            <div className="code-block">
              <div className="flex items-center gap-2 px-5 py-3 border-b border-white/5">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-zinc-800" />
                  <div className="w-3 h-3 rounded-full bg-zinc-800" />
                  <div className="w-3 h-3 rounded-full bg-zinc-800" />
                </div>
                <span className="text-xs text-zinc-600 font-mono ml-2">agent.ts</span>
              </div>
              <pre className="p-5 text-sm leading-relaxed overflow-x-auto">
<code>{`import { StewardClient } from "@steward/sdk";

const steward = new StewardClient({
  baseUrl: "https://api.steward.fi",
  tenantId: "eliza-cloud",
  apiKey: process.env.STEWARD_KEY,
});

// Create wallet for agent
const agent = await steward.createWallet(
  "trading-agent-01",
  "Alpha Trader"
);
// → { walletAddress: "0x7a3...", id: "trading-agent-01" }

// Sign a transaction (policy-checked)
const tx = await steward.signTransaction(
  "trading-agent-01",
  {
    to: "0xdead...beef",
    value: "500000000000000000", // 0.5 ETH
    chainId: 8453, // Base
  }
);
// → { txHash: "0xabc..." }
// or → { status: "pending_approval", results: [...] }`}</code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* Platform section */}
      <section id="platforms" className="py-24 px-6 border-t border-white/5 bg-gradient-to-b from-transparent to-green-500/[0.02]">
        <div className="max-w-5xl mx-auto text-center">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            Designed to embed
          </h2>
          <p className="text-zinc-400 max-w-2xl mx-auto mb-16 leading-relaxed">
            Steward is white-label infrastructure. Agent platforms bring their own UI, users, and approval flows.
            Steward handles the wallet, the keys, and the policy enforcement.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-left">
            {[
              {
                title: "Agent Frameworks",
                desc: "Eliza, AutoGPT, CrewAI. Any agent that needs a wallet can use Steward via the SDK. No framework lock-in.",
                example: "eliza-cloud",
              },
              {
                title: "Token Launchpads",
                desc: "Agents launch tokens, earn fees, pay hosting. Steward manages the treasury with user-set spending rules.",
                example: "waifu.fun",
              },
              {
                title: "Multi-Agent Platforms",
                desc: "Hundreds of agents, one Steward instance. Each gets isolated wallets, policies, and audit trails.",
                example: "milady-cloud",
              },
            ].map((p) => (
              <div key={p.title} className="p-6 rounded-2xl border border-white/5 bg-white/[0.01]">
                <div className="text-xs font-mono text-green-400/60 mb-3">{p.example}</div>
                <h3 className="text-lg font-semibold mb-2">{p.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{p.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture */}
      <section className="py-24 px-6 border-t border-white/5">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Architecture</h2>
            <p className="text-zinc-500 max-w-xl mx-auto">
              Modular packages. Use what you need.
            </p>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {[
              { name: "@steward/shared", desc: "Types & constants" },
              { name: "@steward/vault", desc: "Encrypted keystore" },
              { name: "@steward/policy-engine", desc: "Rule evaluation" },
              { name: "@steward/db", desc: "Drizzle + Postgres" },
              { name: "@steward/api", desc: "Hono REST API" },
              { name: "@steward/sdk", desc: "Client SDK" },
            ].map((pkg) => (
              <div key={pkg.name} className="p-4 rounded-xl border border-white/5 bg-white/[0.01] text-center">
                <div className="text-xs font-mono text-green-400 mb-1.5 truncate">{pkg.name}</div>
                <div className="text-xs text-zinc-600">{pkg.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-6 border-t border-white/5">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            Give your agents wallets
          </h2>
          <p className="text-zinc-400 mb-10 max-w-lg mx-auto leading-relaxed">
            Open source, self-hostable, zero rent. Start building with Steward today.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <a
              href="https://github.com/0xSolace/steward"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-white text-black font-semibold px-7 py-3.5 rounded-xl hover:bg-zinc-200 transition-colors"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
              Get Started
            </a>
            <a
              href="/dashboard"
              className="inline-flex items-center gap-1 text-zinc-400 hover:text-white font-medium px-7 py-3.5 rounded-xl border border-zinc-800 hover:border-zinc-600 transition-colors"
            >
              Open Dashboard →
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/5 py-8 px-6">
        <div className="max-w-5xl mx-auto flex items-center justify-between text-xs text-zinc-600">
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-green-500/20 flex items-center justify-center text-green-400 text-[10px] font-bold">S</div>
            <span>Steward</span>
          </div>
          <div className="flex items-center gap-6">
            <a href="https://github.com/0xSolace/steward" className="hover:text-zinc-400 transition-colors">GitHub</a>
            <span>Built for Synthesis 2026</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
