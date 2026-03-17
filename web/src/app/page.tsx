"use client";

import { motion, useScroll, useTransform } from "framer-motion";
import Image from "next/image";
import { useRef } from "react";
import { Nav } from "@/components/nav";
import { Reveal, StaggerContainer, StaggerItem } from "@/components/motion-wrapper";
import { CodeBlock } from "@/components/code-block";

const easeOutExpo: [number, number, number, number] = [0.16, 1, 0.3, 1];

// --- Hero Section ---
function Hero() {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"],
  });
  const opacity = useTransform(scrollYProgress, [0, 0.5], [1, 0]);
  const y = useTransform(scrollYProgress, [0, 0.5], [0, 80]);

  return (
    <section ref={ref} className="relative min-h-screen flex items-end pb-24 md:pb-32 px-6 md:px-10 pt-24">
      {/* Grid lines background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-[20%] w-px h-full bg-border-subtle opacity-40" />
        <div className="absolute top-0 left-[40%] w-px h-full bg-border-subtle opacity-20" />
        <div className="absolute top-0 left-[70%] w-px h-full bg-border-subtle opacity-30" />
        <div className="absolute top-[30%] left-0 w-full h-px bg-border-subtle opacity-20" />
        <div className="absolute top-[60%] left-0 w-full h-px bg-border-subtle opacity-15" />
      </div>

      {/* Compass star watermark */}
      <div className="absolute top-1/2 right-[5%] -translate-y-1/2 opacity-[0.04] pointer-events-none hidden lg:block">
        <Image src="/logo.png" alt="" width={600} height={600} className="w-[500px] h-[500px]" />
      </div>

      <motion.div style={{ opacity, y }} className="relative max-w-[1400px] mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-end">
          {/* Left: headline */}
          <div className="lg:col-span-7">
            <motion.p
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, ease: easeOutExpo, delay: 0.1 }}
              className="text-sm text-text-tertiary tracking-widest uppercase mb-6"
            >
              The policy layer for autonomous finance
            </motion.p>

            <motion.h1
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, ease: easeOutExpo, delay: 0.2 }}
              className="font-display text-hero font-800 leading-[0.92] tracking-[-0.03em]"
            >
              Agents move money.
              <br />
              <span className="text-[oklch(0.75_0.15_55)]">Steward governs how.</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: easeOutExpo, delay: 0.4 }}
              className="mt-8 text-lg md:text-xl text-text-secondary max-w-xl leading-relaxed"
            >
              Policy-enforced signing. Scoped wallets. Human-in-the-loop approvals.
              The open-source governance layer for any agent framework.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: easeOutExpo, delay: 0.55 }}
              className="mt-10 flex items-center gap-5"
            >
              <a
                href="/dashboard"
                className="px-6 py-3 bg-accent text-bg font-medium text-sm hover:bg-accent-hover transition-colors"
              >
                Launch Dashboard
              </a>
              <a
                href="https://github.com/0xSolace/steward"
                target="_blank"
                rel="noopener noreferrer"
                className="px-6 py-3 border border-border text-text-secondary text-sm hover:text-text hover:border-text-tertiary transition-colors"
              >
                View on GitHub
              </a>
            </motion.div>
          </div>

          {/* Right: floating code preview */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.7, ease: easeOutExpo, delay: 0.5 }}
            className="lg:col-span-5 hidden lg:block"
          >
            <div className="border border-border bg-bg-elevated">
              <CodeBlock
                filename="configure-agent.ts"
                language="typescript"
                typeEffect
                code={`import { StewardClient } from "@stwd/sdk"

const steward = new StewardClient({
  baseUrl: "https://api.steward.fi",
  tenantId: "my-platform",
})

const wallet = await steward.createWallet(
  "trading-agent-01",
  "DeFi Trading Bot"
)

await steward.setPolicies(wallet.id, [
  { type: "spending-limit",
    config: { maxPerTx: "1e18",
              maxPerDay: "10e18" } },
  { type: "approved-addresses",
    config: { addresses: [
      "0xUniswap...",
      "0xTreasury..."] } },
  { type: "human-approval",
    config: { threshold: "5e18" } },
])`}
              />
            </div>
          </motion.div>
        </div>
      </motion.div>
    </section>
  );
}

// --- Problem Statement ---
function ProblemSection() {
  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44">
      <div className="max-w-[1400px] mx-auto">
        <Reveal direction="up" delay={0}>
          <p className="text-sm text-text-tertiary tracking-widest uppercase mb-8">
            The problem
          </p>
        </Reveal>
        <Reveal direction="up" delay={0.1}>
          <h2 className="font-display text-hero-sm font-800 tracking-tight leading-[1.05] max-w-3xl">
            Agents sign whatever they want.
            <br />
            That&apos;s{" "}
            <span className="text-[oklch(0.75_0.15_55)]">the problem</span>.
          </h2>
        </Reveal>
        <Reveal direction="up" delay={0.2}>
          <p className="mt-8 text-lg text-text-secondary max-w-2xl leading-relaxed">
            Trading bots, treasury managers, prediction markets, reward systems.
            Agents are already moving real money. But every framework ships the same thing:
            a raw key in an env var, no spending limits, no restrictions.
            One hallucination, one prompt injection, and the wallet is drained.
            No undo on a blockchain.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

// --- How It Works ---
function HowItWorksSection() {
  const steps = [
    {
      num: "01",
      label: "Request",
      desc: "Agent calls steward.signTransaction() with destination, value, and calldata. Never touches the private key.",
    },
    {
      num: "02",
      label: "Evaluate",
      desc: "Policy engine checks spending limits, approved addresses, rate limits, and time windows.",
    },
    {
      num: "03",
      label: "Decide",
      desc: "Auto-approve below threshold, queue for human review above it, or reject outright. Webhooks fire on every state change.",
    },
    {
      num: "04",
      label: "Sign",
      desc: "Key is decrypted in-process, transaction is signed and broadcast to Base. Key is discarded immediately.",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <Reveal>
          <p className="text-sm text-text-tertiary tracking-widest uppercase mb-8">
            How it works
          </p>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-px bg-border-subtle mt-12">
          {steps.map((step, i) => (
            <Reveal key={step.num} delay={i * 0.1} className="bg-bg p-8 md:p-10">
              <span className="font-display text-5xl font-800 text-border tracking-tight">
                {step.num}
              </span>
              <h3 className="font-display text-xl font-700 mt-6 mb-3">
                {step.label}
              </h3>
              <p className="text-sm text-text-secondary leading-relaxed">
                {step.desc}
              </p>
            </Reveal>
          ))}
        </div>

        {/* Flow diagram */}
        <Reveal delay={0.3} className="mt-16">
          <FlowDiagram />
        </Reveal>
      </div>
    </section>
  );
}

function FlowDiagram() {
  const nodes = [
    { label: "Agent", sub: "SDK call" },
    { label: "Policy Engine", sub: "Evaluate rules" },
    { label: "Decision", sub: "Approve / Queue / Reject" },
    { label: "Vault", sub: "Sign & broadcast" },
  ];

  return (
    <div className="flex items-center justify-between overflow-x-auto py-6">
      {nodes.map((node, i) => (
        <div key={node.label} className="flex items-center flex-1 min-w-0">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.15, duration: 0.4, ease: [0.25, 1, 0.5, 1] }}
            className="border border-border px-5 py-3 bg-bg-elevated flex-shrink-0"
          >
            <div className="text-sm font-display font-700">{node.label}</div>
            <div className="text-xs text-text-tertiary mt-0.5">{node.sub}</div>
          </motion.div>
          {i < nodes.length - 1 && (
            <motion.div
              initial={{ opacity: 0, scaleX: 0 }}
              whileInView={{ opacity: 1, scaleX: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 + 0.2, duration: 0.3, ease: [0.25, 1, 0.5, 1] }}
              className="flex-1 h-px bg-border origin-left mx-1 relative min-w-[16px]"
            >
              <div className="absolute right-0 top-1/2 -translate-y-1/2 w-0 h-0 border-t-[4px] border-t-transparent border-b-[4px] border-b-transparent border-l-[6px] border-l-border" />
            </motion.div>
          )}
        </div>
      ))}
    </div>
  );
}

// --- SDK Section ---
function SDKSection() {
  const snippets = [
    {
      filename: "create-wallet.ts",
      code: `const agent = await steward.createWallet(
  "agent-alpha",
  "Trading Agent"
)

console.log(agent.walletAddress)
// 0x7a3f...4e2b`,
    },
    {
      filename: "sign-transaction.ts",
      code: `const result = await steward.signTransaction(
  "agent-alpha",
  {
    to: "0xdead...beef",
    value: "500000000000000", // 0.0005 ETH
    chainId: 8453,           // Base
  }
)

// result.txHash or result.status === "pending_approval"`,
    },
    {
      filename: "policies.ts",
      code: `const policies = await steward.getPolicies("agent-alpha")

await steward.setPolicies("agent-alpha", [
  {
    id: "spend-limit",
    type: "spending-limit",
    enabled: true,
    config: {
      maxPerTx: "1000000000000000",  // 0.001 ETH
      maxPerDay: "10000000000000000", // 0.01 ETH
    },
  },
])`,
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-16">
          <div className="lg:col-span-4">
            <Reveal>
              <p className="text-sm text-text-tertiary tracking-widest uppercase mb-8">
                SDK
              </p>
            </Reveal>
            <Reveal delay={0.1}>
              <h2 className="font-display text-hero-sm font-800 tracking-tight leading-[1.05]">
                Three calls.
                <br />
                Full control.
              </h2>
            </Reveal>
            <Reveal delay={0.2}>
              <p className="mt-6 text-text-secondary leading-relaxed">
                The Steward SDK handles wallet creation, policy-checked signing,
                and rule management. TypeScript-first. Works with any agent framework.
              </p>
            </Reveal>
            <Reveal delay={0.3}>
              <div className="mt-8">
                <code className="text-xs text-text-tertiary font-mono">
                  npm i @stwd/sdk
                </code>
              </div>
            </Reveal>
          </div>

          <div className="lg:col-span-8 space-y-4">
            {snippets.map((snippet, i) => (
              <Reveal key={snippet.filename} delay={i * 0.1} direction="right">
                <div className="border border-border bg-bg-elevated">
                  <CodeBlock
                    filename={snippet.filename}
                    language="typescript"
                    code={snippet.code}
                  />
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

// --- For Platforms ---
function PlatformsSection() {
  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-16">
          <div className="lg:col-span-7">
            <Reveal>
              <p className="text-sm text-text-tertiary tracking-widest uppercase mb-8">
                Built for real operations
              </p>
            </Reveal>
            <Reveal delay={0.1}>
              <h2 className="font-display text-hero-sm font-800 tracking-tight leading-[1.05]">
                Multi-tenant by default
              </h2>
            </Reveal>
            <Reveal delay={0.2}>
              <p className="mt-6 text-lg text-text-secondary leading-relaxed max-w-xl">
                Run one Steward instance for thousands of agents across isolated tenants.
                Each tenant gets its own API key, policies, and webhook endpoints.
                Self-hosted. No per-transaction toll. No vendor lock-in.
              </p>
            </Reveal>
          </div>

          <div className="lg:col-span-5 flex flex-col justify-center">
            <StaggerContainer staggerDelay={0.12} className="space-y-6">
              {[
                {
                  name: "DeFi & Trading",
                  desc: "Trading bots, yield agents, and liquidity managers with enforced spending limits and approved counterparties",
                },
                {
                  name: "Prediction Markets",
                  desc: "Autonomous market makers with risk boundaries and position limits",
                },
                {
                  name: "Treasuries & Rewards",
                  desc: "DAO treasuries, perks systems, and micro-payment agents with multi-party approval flows",
                },
                {
                  name: "RWA & Settlement",
                  desc: "Commodity finance, collateral management, and tokenized asset operations",
                },
              ].map((tenant) => (
                <StaggerItem key={tenant.name}>
                  <div className="border-l-2 border-border pl-6 py-2 hover:border-accent transition-colors">
                    <div className="font-display font-700 text-lg">{tenant.name}</div>
                    <div className="text-sm text-text-secondary mt-1">{tenant.desc}</div>
                  </div>
                </StaggerItem>
              ))}
            </StaggerContainer>
          </div>
        </div>
      </div>
    </section>
  );
}

// --- Open Source Banner ---
function OpenSourceSection() {
  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto text-center">
        <Reveal>
          <p className="text-sm text-text-tertiary tracking-widest uppercase mb-8">
            Open source
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <h2 className="font-display text-hero-sm font-800 tracking-tight leading-[1.05] max-w-2xl mx-auto">
            Infrastructure, not rent-seeking middleware.
          </h2>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="mt-6 text-lg text-text-secondary leading-relaxed max-w-xl mx-auto">
            No tolls. No per-transaction fees. MIT-licensed, self-hostable,
            built to be the foundation you own, not a dependency you rent.
          </p>
        </Reveal>
        <Reveal delay={0.3}>
          <div className="mt-10 flex items-center justify-center gap-5">
            <a
              href="https://github.com/0xSolace/steward"
              target="_blank"
              rel="noopener noreferrer"
              className="px-6 py-3 border border-border text-text-secondary text-sm hover:text-text hover:border-text-tertiary transition-colors"
            >
              Browse the source
            </a>
            <a
              href="https://npmjs.com/package/@stwd/sdk"
              target="_blank"
              rel="noopener noreferrer"
              className="px-6 py-3 border border-border text-text-secondary text-sm hover:text-text hover:border-text-tertiary transition-colors"
            >
              npm i @stwd/sdk
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
            <Image src="/logo.png" alt="" width={18} height={18} className="w-[18px] h-[18px] opacity-60" />
            <span className="font-display text-base font-bold tracking-tight">steward</span>
          </div>
          <p className="text-xs text-text-tertiary mt-1">
            The trust layer for autonomous finance. Open source.
          </p>
        </div>
        <div className="flex items-center gap-6 text-sm text-text-tertiary">
          <a
            href="https://github.com/0xSolace/steward"
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
          <a
            href="https://docs.steward.fi"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text transition-colors"
          >
            Docs
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
      <ProblemSection />
      <HowItWorksSection />
      <SDKSection />
      <PlatformsSection />
      <OpenSourceSection />
      <Footer />
    </main>
  );
}
