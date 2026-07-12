"use client";

import { motion, useScroll, useTransform } from "framer-motion";
import Image from "next/image";
import { useRef } from "react";
import { CodeBlock } from "@/components/code-block";
import { Reveal, StaggerContainer, StaggerItem } from "@/components/motion-wrapper";
import { Nav } from "@/components/nav";

const easeOutExpo: [number, number, number, number] = [0.16, 1, 0.3, 1];
const accent = "text-[oklch(0.78_0.15_55)]";

// --- Hero Section ---
// Asymmetric split: left headline + neutrality line, right = a governed-action
// panel showing a real StewardClient call flow with an allow, an approval hold,
// and a policy-denied line. Policy-denied is a feature, so it is shown.
function Hero() {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"],
  });
  const opacity = useTransform(scrollYProgress, [0, 0.5], [1, 0]);
  const y = useTransform(scrollYProgress, [0, 0.5], [0, 80]);

  return (
    <section
      ref={ref}
      className="relative h-[100dvh] min-h-[560px] max-h-[1100px] flex items-center px-6 md:px-10 pt-16 overflow-hidden"
    >
      {/* Single structural line, no decoration kit */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-[62%] w-px h-full bg-border-subtle opacity-30 hidden lg:block" />
      </div>

      <motion.div style={{ opacity, y }} className="relative max-w-[1400px] mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14 items-center">
          {/* Left: headline */}
          <div className="lg:col-span-7">
            <p
              className="hero-fade font-mono text-[0.7rem] uppercase tracking-[0.18em] text-text-tertiary mb-6"
              style={{ animationDelay: "0.05s" }}
            >
              Open source, MIT
            </p>

            <h1
              className="hero-rise font-display text-hero-landing font-extrabold leading-[0.94] tracking-[-0.035em] text-balance"
              style={{ animationDelay: "0.15s" }}
            >
              Give agents power.
              <br />
              <span className={accent}>Never the keys.</span>
            </h1>

            <p
              className="hero-rise mt-6 text-lg text-text-secondary max-w-lg leading-relaxed text-pretty"
              style={{ animationDelay: "0.3s" }}
            >
              The open authority and execution layer for AI agents. Policy before every privileged
              action. Human approval when it matters. A full audit trail, always.
            </p>

            <div
              className="hero-fade mt-6 flex flex-wrap items-center gap-x-3 gap-y-1.5 font-mono text-[0.7rem] uppercase tracking-wider text-text-tertiary"
              style={{ animationDelay: "0.42s" }}
            >
              <span>Any model</span>
              <span className="text-border">/</span>
              <span>Any runtime</span>
              <span className="text-border">/</span>
              <span>Any chain</span>
              <span className="text-border">/</span>
              <span className={accent}>Your infrastructure</span>
            </div>

            <div
              className="hero-rise mt-8 flex flex-wrap items-center gap-4"
              style={{ animationDelay: "0.5s" }}
            >
              <a
                href="/dashboard"
                className="group px-6 py-3 bg-accent text-bg font-semibold text-sm rounded-sm hover:bg-accent-hover transition-colors inline-flex items-center gap-2"
              >
                Launch Dashboard
                <span className="transition-transform group-hover:translate-x-0.5">&rarr;</span>
              </a>
              <a
                href="https://github.com/Steward-Fi/steward"
                target="_blank"
                rel="noopener noreferrer"
                className="px-6 py-3 border border-border text-text-secondary text-sm rounded-sm hover:text-text hover:border-text-tertiary transition-colors"
              >
                View Source
              </a>
            </div>
          </div>

          {/* Right: governed-action panel */}
          <div
            className="hero-rise lg:col-span-5 hidden lg:block"
            style={{ animationDelay: "0.4s" }}
          >
            <div className="border border-border bg-bg-elevated rounded-sm shadow-[0_24px_80px_-20px_rgba(0,0,0,0.7)]">
              <CodeBlock
                filename="agent.ts"
                language="typescript"
                code={`// Agent asks. Steward decides.
const swap = await steward.signTransaction(agentId, {
  to: "0xUniswapRouter",
  value: "500000000000000000",
})
// -> policy check -> sign -> "0x9f3c..."

// Over the daily cap: held for a human
// -> { status: "pending_approval" }

// Not on the allowlist: denied
// -> PolicyDenied: destination not permitted`}
              />
            </div>
          </div>
        </div>
      </motion.div>
    </section>
  );
}

// --- Secret sprawl problem ---
// Asymmetric: sticky claim on the left, prose + a tight failure ledger on the right.
function SecretSprawlSection() {
  const failures = [
    {
      k: "keys in env",
      v: "API keys and private keys sit in environment variables, readable by anything in the process.",
    },
    {
      k: "policy in prompts",
      v: "Permissions live in the system prompt. A jailbreak, a bad tool call, and the boundary is gone.",
    },
    {
      k: "no revocation",
      v: "A leaked key stays valid until someone notices and rotates it everywhere by hand.",
    },
    {
      k: "no audit",
      v: "No record of who asked for what, what was allowed, and what actually executed.",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
        <div className="lg:col-span-5 lg:sticky lg:top-28">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              The problem
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
              One Steward credential.
              <br />
              <span className={accent}>Zero raw secrets.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 text-text-secondary leading-relaxed max-w-md text-pretty">
              Handing an agent an API key or a signing key is not security. It is a secret with no
              boundary, no revocation, and no record. Steward gives the agent one scoped credential
              and keeps the real authority behind a policy plane.
            </p>
          </Reveal>
        </div>

        <div className="lg:col-span-7">
          <StaggerContainer
            staggerDelay={0.08}
            className="border-t border-border-subtle divide-y divide-border-subtle"
          >
            {failures.map((f) => (
              <StaggerItem key={f.k}>
                <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,10rem)_1fr] gap-2 sm:gap-8 py-6">
                  <div className="font-mono text-sm text-[oklch(0.78_0.15_55)] tracking-tight">
                    {f.k}
                  </div>
                  <p className="text-[0.95rem] text-text-secondary leading-relaxed text-pretty">
                    {f.v}
                  </p>
                </div>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </div>
      </div>
    </section>
  );
}

// --- The trust boundary pipeline: the spine of the page ---
// Sticky claim on the left, stepped-reveal vertical flow on the right.
// Amber marks ONLY the decision points (identity/capability, policy/approval,
// simulation/execution). Works with reduced motion (reveals resolve to visible).
function PipelineSection() {
  const steps = [
    {
      idx: "00",
      label: "Agent intent",
      body: "The model asks for a privileged action. It never holds the underlying authority.",
      decision: false,
    },
    {
      idx: "01",
      label: "Identity + capability",
      body: "Steward resolves who is asking and which scoped capabilities they hold.",
      decision: true,
    },
    {
      idx: "02",
      label: "Policy + approval",
      body: "Rules evaluate under default-deny. Anything over a threshold routes to a human.",
      decision: true,
    },
    {
      idx: "03",
      label: "Simulation + execution",
      body: "The action is simulated, then signed and executed across the target rail.",
      decision: true,
    },
    {
      idx: "04",
      label: "Audit + reconciliation",
      body: "Every decision and effect lands in an append-only, tamper-evident record.",
      decision: false,
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-36 border-t border-border-subtle overflow-hidden">
      <div className="absolute top-1/4 right-[10%] w-[520px] h-[520px] rounded-full pointer-events-none opacity-[0.05] blur-[130px] bg-[oklch(0.75_0.15_55)]" />
      <div className="relative max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
        <div className="lg:col-span-5 lg:sticky lg:top-28">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              The trust boundary
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
              Between agent intent and <span className={accent}>real-world effects.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 text-text-secondary leading-relaxed max-w-md text-pretty">
              Every privileged action crosses the same boundary. The model never needs custody of
              the underlying authority. It asks, and Steward decides, executes, and records.
            </p>
          </Reveal>
          <Reveal delay={0.18}>
            <div className="mt-8 inline-flex items-center gap-2.5 border border-border rounded-sm px-3.5 py-2 bg-bg-elevated">
              <span className="w-1.5 h-1.5 rounded-full bg-[oklch(0.78_0.15_55)]" />
              <span className="font-mono text-xs text-text-secondary tracking-tight">
                amber marks the decision points
              </span>
            </div>
          </Reveal>
        </div>

        <div className="lg:col-span-7">
          <ol className="relative">
            {/* Spine line */}
            <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border-subtle" />
            {steps.map((step, i) => (
              <motion.li
                key={step.idx}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.6 }}
                transition={{ duration: 0.5, delay: i * 0.08, ease: easeOutExpo }}
                className="relative pl-12 pb-10 last:pb-0"
              >
                {/* Node */}
                <span
                  className={`absolute left-0 top-1 flex items-center justify-center w-[23px] h-[23px] rounded-full border ${
                    step.decision
                      ? "border-[oklch(0.75_0.15_55)] bg-[oklch(0.2_0.04_55)]"
                      : "border-border bg-bg"
                  }`}
                >
                  <span
                    className={`w-[7px] h-[7px] rounded-full ${
                      step.decision ? "bg-[oklch(0.78_0.15_55)]" : "bg-text-tertiary"
                    }`}
                  />
                </span>
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-xs text-text-tertiary tracking-tight">
                    {step.idx}
                  </span>
                  <h3 className="font-display text-lg md:text-xl font-bold leading-snug">
                    {step.label}
                  </h3>
                  {step.decision && (
                    <span className="font-mono text-[10px] uppercase tracking-wider text-[oklch(0.8_0.14_55)] border border-[oklch(0.4_0.08_55)] rounded-full px-2 py-0.5">
                      decision
                    </span>
                  )}
                </div>
                <p className="mt-2 text-[0.95rem] text-text-secondary leading-relaxed max-w-lg text-pretty">
                  {step.body}
                </p>
              </motion.li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}

// --- Execution proof: real capabilities ---
// Sticky claim + a border-divided ledger of real capabilities. No card grid.
// Amber verbs mark the enforced decision moments.
function ExecutionSection() {
  const rows = [
    {
      tag: "evm.swap",
      title: "Governed EVM swap",
      body: "Prepare, execute, reconcile with simulation gates and durable intents. A dropped connection never means a lost or double transaction.",
    },
    {
      tag: "trade.session",
      title: "Venue-scoped trading",
      body: "Hyperliquid and Polymarket sessions with spend caps and a freeze switch. Authority is bounded to a venue, a size, and a window.",
    },
    {
      tag: "proxy.inject",
      title: "Credential proxy",
      body: "Outbound API calls get their credentials injected at the edge with zero key exposure to the agent, stripped from logs.",
    },
    {
      tag: "grant.scope",
      title: "Capability grants",
      body: "Scoped API access, not blanket tokens. github.pr.comment is allowed. github.repo.delete is denied. The grant is the contract.",
    },
    {
      tag: "sign.freeze",
      title: "Atomic freeze",
      body: "One kill switch halts all signing across every wallet and session, instantly, without redeploying the agent.",
    },
    {
      tag: "audit.log",
      title: "Append-only audit",
      body: "An HMAC-chained record of every request, decision, and effect. Tamper-evident and machine-readable end to end.",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
        <div className="lg:col-span-4 lg:sticky lg:top-28">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              Execution
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
              From API access to financial execution.{" "}
              <span className={accent}>One policy plane.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 text-text-secondary leading-relaxed max-w-sm text-pretty">
              These are not roadmap items. Signing, trading, proxying, and grants all run behind the
              same boundary and land in the same audit trail.
            </p>
          </Reveal>
        </div>

        <div className="lg:col-span-8">
          <StaggerContainer
            staggerDelay={0.07}
            className="border-t border-border-subtle divide-y divide-border-subtle"
          >
            {rows.map((r) => (
              <StaggerItem key={r.tag}>
                <div className="group py-6 grid grid-cols-1 sm:grid-cols-[1fr_1.6fr] gap-2 sm:gap-8">
                  <div>
                    <h3 className="font-display text-lg font-bold leading-snug">{r.title}</h3>
                    <span className="font-mono text-xs text-text-tertiary group-hover:text-[oklch(0.78_0.15_55)] transition-colors">
                      {r.tag}
                    </span>
                  </div>
                  <p className="text-[0.95rem] text-text-secondary leading-relaxed text-pretty">
                    {r.body}
                  </p>
                </div>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </div>
      </div>
    </section>
  );
}

// --- SDK Section: real surface ---
function SDKSection() {
  const snippets = [
    {
      filename: "trade-session.ts",
      code: `// A venue-scoped session: bounded size, freezable
const session = await steward.tradeSessions.create({
  agentId,
  venue: "hyperliquid",
  spendCapUsd: "5000",
  expiresIn: "24h",
})

await steward.trade.hyperliquid.submitOrder({
  sessionId: session.id,
  market: "ETH", side: "buy", sizeUsd: "250",
})
// Over the cap or after freeze: rejected at the edge`,
    },
    {
      filename: "capability-grant.ts",
      code: `// Scoped API access, not a blanket token
await steward.setPolicies(agentId, [
  { type: "capability",
    config: { allow: ["github.pr.comment"] } },
  { type: "capability",
    config: { deny: ["github.repo.delete"] } },
  { type: "spending-limit",
    config: { maxPerTx: "1e18", maxPerDay: "10e18" } },
])`,
    },
    {
      filename: "proxy.ts",
      code: `// Credential injected at the edge, never in the agent
const openai = new OpenAI({
  baseURL: \`\${process.env.STEWARD_URL}/proxy/openai/v1\`,
})

const res = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "..." }],
})
// Rate-limited, cost-attributed, audited`,
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16">
        <div className="lg:col-span-4 lg:sticky lg:top-28 self-start">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              SDK
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02]">
              Ask for the action.
              <br />
              <span className={accent}>Steward enforces it.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.15}>
            <p className="mt-6 text-text-secondary leading-relaxed text-pretty">
              One TypeScript client for signing, trading, grants, and proxying. It works with any
              agent framework and any model, because the authority lives in Steward, not the prompt.
            </p>
          </Reveal>
          <Reveal delay={0.25}>
            <div className="mt-7 inline-flex items-center gap-2 border border-border rounded-sm px-3 py-2 bg-bg-elevated">
              <span className="text-text-tertiary font-mono text-xs">$</span>
              <code className="text-sm text-text font-mono">npm i @stwd/sdk</code>
            </div>
          </Reveal>
        </div>

        <div className="lg:col-span-8 space-y-4">
          {snippets.map((snippet, i) => (
            <Reveal key={snippet.filename} delay={i * 0.1} direction="right">
              <div className="border border-border bg-bg-elevated rounded-sm">
                <CodeBlock filename={snippet.filename} language="typescript" code={snippet.code} />
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// --- Built for agents ---
// Sticky claim + a two-column divided ledger of what agent-native means.
function AgentsSection() {
  const traits = [
    {
      t: "Autonomous execution",
      d: "Actions fire at machine speed without a human in the loop, until policy says otherwise.",
    },
    {
      t: "Persistent delegated authority",
      d: "Authority is granted once and bounded, not re-entered per session like a human login.",
    },
    {
      t: "Bounded financial permissions",
      d: "Caps, allowlists, and windows are enforced in the vault, not suggested in a prompt.",
    },
    {
      t: "Ambiguous-outcome recovery",
      d: "Durable intents reconcile a dropped call so nothing is lost or executed twice.",
    },
    {
      t: "Machine-readable audit",
      d: "The record is structured for programs, not just for a human reading a dashboard.",
    },
    {
      t: "Emergency operator control",
      d: "A human can freeze everything instantly, without shipping new code to the agent.",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
        <div className="lg:col-span-5 lg:sticky lg:top-28">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              Agent-native
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
              Built for agents,{" "}
              <span className={accent}>not adapted from human infrastructure.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 text-text-secondary leading-relaxed max-w-md text-pretty">
              Human auth assumes a person clicks to confirm. Agents act continuously, hold authority
              across sessions, and fail in ambiguous ways. Steward is designed for that reality.
            </p>
          </Reveal>
        </div>

        <div className="lg:col-span-7">
          <StaggerContainer
            staggerDelay={0.07}
            className="grid grid-cols-1 sm:grid-cols-2 border-t border-l border-border-subtle"
          >
            {traits.map((tr) => (
              <StaggerItem key={tr.t}>
                <div className="h-full border-b border-r border-border-subtle p-6">
                  <h3 className="font-display text-base font-bold mb-2 leading-snug">{tr.t}</h3>
                  <p className="text-sm text-text-secondary leading-relaxed text-pretty">{tr.d}</p>
                </div>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </div>
      </div>
    </section>
  );
}

// --- Specs strip ---
function SpecsSection() {
  const specs = [
    { value: "AES-256-GCM", label: "Encryption at rest" },
    { value: "Default deny", label: "Policy model" },
    { value: "7 EVM + Solana", label: "Chains supported" },
    { value: "< 50ms", label: "Proxy overhead" },
  ];

  return (
    <section className="relative px-6 md:px-10 py-20 md:py-24 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <Reveal>
          <p className="text-text-secondary text-sm mb-8 max-w-2xl">
            Built to enterprise security standards. Audited paths, encrypted at rest, fast enough to
            sit in front of every call.
          </p>
        </Reveal>
        <div className="grid grid-cols-2 lg:grid-cols-4 border-t border-l border-border-subtle">
          {specs.map((spec, i) => (
            <Reveal
              key={spec.label}
              delay={i * 0.08}
              className="border-b border-r border-border-subtle p-7 md:p-8"
            >
              <div className="font-mono text-xl md:text-2xl font-bold tracking-tight tabular-nums">
                {spec.value}
              </div>
              <div className="text-xs text-text-secondary mt-2 tracking-wide uppercase font-mono">
                {spec.label}
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// --- Compact comparison (small, late, not the centerpiece) ---
function ComparisonSection() {
  const rows = [
    { feature: "Source", steward: "Open source, MIT", vendor: "Closed, proprietary" },
    { feature: "Hosting", steward: "Self-host or managed", vendor: "Hosted only" },
    { feature: "Keys and data", steward: "You own them", vendor: "On their infrastructure" },
    {
      feature: "Policy engine",
      steward: "Enforced before every action",
      vendor: "Bolted on, if any",
    },
    { feature: "Agents", steward: "First-class actors", vendor: "Human-paced pricing" },
    {
      feature: "Pricing",
      steward: "No per-transaction toll",
      vendor: "Per-seat + per-transaction",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-28 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
        <div className="lg:col-span-4 lg:sticky lg:top-28">
          <Reveal>
            <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-5">
              Versus closed custody
            </p>
            <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
              Own the rail. <span className={accent}>Don&apos;t rent it.</span>
            </h2>
          </Reveal>
          <Reveal delay={0.1}>
            <p className="mt-6 text-text-secondary leading-relaxed max-w-sm text-pretty">
              Closed custody vendors hold your keys, meter your growth, and give you no way out.
              Steward is the same authority on infrastructure you control.
            </p>
          </Reveal>
        </div>

        <div className="lg:col-span-8">
          <Reveal delay={0.1}>
            <div className="hidden sm:block border border-border rounded-sm overflow-hidden">
              <div className="grid grid-cols-[1.2fr_1fr_1fr] bg-bg-elevated border-b border-border">
                <div className="px-5 py-3.5 text-xs uppercase tracking-wider text-text-tertiary font-mono">
                  Capability
                </div>
                <div className="px-5 py-3.5 flex items-center gap-2 border-l border-border-subtle bg-[oklch(0.2_0.04_55)]/40 border-t-2 border-t-[oklch(0.75_0.15_55)]">
                  <Image src="/logo.png" alt="" width={16} height={16} className="w-4 h-4" />
                  <span className="font-display font-bold text-sm">Steward</span>
                </div>
                <div className="px-5 py-3.5 text-sm text-text-tertiary border-l border-border-subtle font-medium">
                  Closed custody vendors
                </div>
              </div>
              {rows.map((row, i) => (
                <motion.div
                  key={row.feature}
                  initial={{ opacity: 0, y: 8 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.6 }}
                  transition={{ duration: 0.4, delay: i * 0.05, ease: easeOutExpo }}
                  className={`grid grid-cols-[1.2fr_1fr_1fr] ${
                    i !== rows.length - 1 ? "border-b border-border-subtle" : ""
                  }`}
                >
                  <div className="px-5 py-3.5 text-sm text-text-secondary flex items-center">
                    {row.feature}
                  </div>
                  <div className="px-5 py-3.5 text-sm text-text font-medium flex items-center gap-2.5 border-l border-border-subtle bg-[oklch(0.2_0.04_55)]/40">
                    <span className="text-[oklch(0.8_0.16_55)] flex-shrink-0 font-bold">
                      &#10003;
                    </span>
                    {row.steward}
                  </div>
                  <div className="px-5 py-3.5 text-sm text-text-tertiary flex items-center gap-2.5 border-l border-border-subtle">
                    <span className="text-text-tertiary flex-shrink-0">&#10005;</span>
                    {row.vendor}
                  </div>
                </motion.div>
              ))}
            </div>

            <div className="sm:hidden border border-border rounded-sm divide-y divide-border-subtle overflow-hidden">
              {rows.map((row) => (
                <div key={row.feature} className="p-5">
                  <div className="text-xs uppercase tracking-wider text-text-tertiary font-mono mb-3">
                    {row.feature}
                  </div>
                  <div className="flex items-start gap-2.5 text-sm text-text">
                    <span className="text-[oklch(0.78_0.15_55)] flex-shrink-0 mt-px">&#10003;</span>
                    <span>
                      <span className="font-medium">Steward</span>{" "}
                      <span className="text-text-secondary">{row.steward}</span>
                    </span>
                  </div>
                  <div className="flex items-start gap-2.5 text-sm text-text-tertiary mt-2">
                    <span className="flex-shrink-0 mt-px">&#10005;</span>
                    <span>
                      Closed vendors {row.vendor.charAt(0).toLowerCase() + row.vendor.slice(1)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

// --- Open by design / CTA (the one centered moment) ---
function OpenSourceSection() {
  const pillars = ["MIT licensed", "Self-hostable", "Vendor-neutral", "No per-transaction toll"];

  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle overflow-hidden">
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
        <div className="w-[700px] h-[700px] rounded-full opacity-[0.06] blur-[140px] bg-[oklch(0.75_0.15_55)]" />
      </div>
      <div className="relative max-w-[1400px] mx-auto text-center">
        <Reveal>
          <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary mb-6">
            Open by design
          </p>
          <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] max-w-3xl mx-auto text-balance">
            Agents can act. <span className={accent}>Steward keeps them accountable.</span>
          </h2>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="mt-7 text-lg text-text-secondary leading-relaxed max-w-xl mx-auto text-pretty">
            MIT-licensed, self-hostable, and vendor-neutral, with no per-transaction toll. Own your
            keys, your policies, your data, and your audit trail, on infrastructure you control.
          </p>
        </Reveal>
        <Reveal delay={0.16}>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-x-3 gap-y-2 font-mono text-[0.7rem] uppercase tracking-wider text-text-tertiary">
            {pillars.map((p, i) => (
              <span key={p} className="flex items-center gap-3">
                {i > 0 && <span className="text-border">/</span>}
                <span>{p}</span>
              </span>
            ))}
          </div>
        </Reveal>
        <Reveal delay={0.24}>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <a
              href="/dashboard"
              className="group px-6 py-3 bg-accent text-bg font-semibold text-sm rounded-sm hover:bg-accent-hover transition-colors inline-flex items-center gap-2"
            >
              Launch Dashboard
              <span className="transition-transform group-hover:translate-x-0.5">&rarr;</span>
            </a>
            <a
              href="https://github.com/Steward-Fi/steward"
              target="_blank"
              rel="noopener noreferrer"
              className="px-6 py-3 border border-border text-text-secondary text-sm rounded-sm hover:text-text hover:border-text-tertiary transition-colors"
            >
              Browse the source
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

// --- Footer ---
function Footer() {
  return (
    <footer className="border-t border-border-subtle px-6 md:px-10 py-12">
      <div className="max-w-[1400px] mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2">
            <Image
              src="/logo.png"
              alt=""
              width={18}
              height={18}
              className="w-[18px] h-[18px] opacity-70"
            />
            <span className="font-display text-base font-bold tracking-tight">steward</span>
          </div>
          <p className="text-xs text-text-tertiary mt-1.5">
            The open authority and execution layer for AI agents.
          </p>
        </div>
        <div className="flex items-center gap-6 text-sm text-text-secondary">
          <a
            href="https://docs.steward.fi"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text transition-colors"
          >
            Docs
          </a>
          <a
            href="https://github.com/Steward-Fi/steward"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text transition-colors"
          >
            GitHub
          </a>
          <a
            href="https://npmjs.com/package/@stwd/sdk"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text transition-colors"
          >
            npm
          </a>
        </div>
      </div>
    </footer>
  );
}

// --- Main Page ---
export default function LandingPage() {
  return (
    <main>
      <Nav />
      <Hero />
      <SecretSprawlSection />
      <PipelineSection />
      <ExecutionSection />
      <SDKSection />
      <AgentsSection />
      <SpecsSection />
      <ComparisonSection />
      <OpenSourceSection />
      <Footer />
    </main>
  );
}
