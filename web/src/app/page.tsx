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
              Agent wallet infrastructure
            </motion.p>

            <motion.h1
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, ease: easeOutExpo, delay: 0.2 }}
              className="font-display text-hero font-800 leading-[0.92] tracking-[-0.03em]"
            >
              Managed wallets
              <br />
              <span className="text-[oklch(0.75_0.15_55)]">for agents</span>
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: easeOutExpo, delay: 0.4 }}
              className="mt-8 text-lg md:text-xl text-text-secondary max-w-xl leading-relaxed"
            >
              Policy enforcement. Multi-tenant isolation. Webhook-driven approvals.
              One SDK call to go from raw keys to governed wallets.
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, ease: easeOutExpo, delay: 0.55 }}
              className="mt-10 flex items-center gap-5"
            >
              <a
                href="https://github.com/0xSolace/steward"
                target="_blank"
                rel="noopener noreferrer"
                className="px-6 py-3 bg-accent text-bg font-medium text-sm hover:bg-accent-hover transition-colors"
              >
                View on GitHub
              </a>
              <a
                href="/dashboard"
                className="px-6 py-3 border border-border text-text-secondary text-sm hover:text-text hover:border-text-tertiary transition-colors"
              >
                Open Dashboard
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
                filename="agent.ts"
                language="typescript"
                typeEffect
                code={`import { StewardClient } from "@steward/sdk"

const steward = new StewardClient({
  baseUrl: "https://api.steward.fi",
  tenantId: "eliza-cloud",
})

const wallet = await steward.createWallet(
  "trading-agent-01",
  "Alpha Trader"
)

const tx = await steward.signTransaction(
  wallet.id,
  {
    to: "0xdead...beef",
    value: "100000000000000",
    chainId: 8453,
  }
)`}
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
            AI agents need wallets.
            <br />
            Raw private keys are{" "}
            <span className="text-[oklch(0.75_0.15_55)]">unacceptable</span>.
          </h2>
        </Reveal>
        <Reveal direction="up" delay={0.2}>
          <p className="mt-8 text-lg text-text-secondary max-w-2xl leading-relaxed">
            Every agent platform solves key management differently. Most get it wrong.
            Hot keys with no limits. No audit trail. No way to stop a rogue agent
            before it drains a wallet. Steward fixes this at the infrastructure layer.
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
      desc: "Agent submits a transaction through the SDK. Includes destination, value, and calldata.",
    },
    {
      num: "02",
      label: "Evaluate",
      desc: "Policy engine checks spending limits, approved addresses, rate limits, and time windows.",
    },
    {
      num: "03",
      label: "Decide",
      desc: "Auto-approve, queue for manual review, or reject. Webhook fires on state change.",
    },
    {
      num: "04",
      label: "Sign",
      desc: "Approved transactions are signed from the agent's managed wallet and broadcast to Base.",
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
  return (
    <div className="flex items-center justify-between gap-2 overflow-x-auto py-6 px-4">
      {[
        { label: "Agent", sub: "SDK call" },
        { label: "Policy Engine", sub: "Evaluate rules" },
        { label: "Decision", sub: "Approve / Queue / Reject" },
        { label: "Vault", sub: "Sign & broadcast" },
      ].map((node, i) => (
        <div key={node.label} className="flex items-center gap-2 flex-shrink-0">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.15, duration: 0.4, ease: [0.25, 1, 0.5, 1] }}
            className="border border-border px-5 py-3 bg-bg-elevated"
          >
            <div className="text-sm font-display font-700">{node.label}</div>
            <div className="text-xs text-text-tertiary mt-0.5">{node.sub}</div>
          </motion.div>
          {i < 3 && (
            <motion.div
              initial={{ opacity: 0, scaleX: 0 }}
              whileInView={{ opacity: 1, scaleX: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.15 + 0.2, duration: 0.3, ease: [0.25, 1, 0.5, 1] }}
              className="w-8 md:w-16 h-px bg-border origin-left flex-shrink-0"
            />
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
                  bun add @steward/sdk
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
                For platforms
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
                No per-transaction rent. No vendor lock-in.
              </p>
            </Reveal>
          </div>

          <div className="lg:col-span-5 flex flex-col justify-center">
            <StaggerContainer staggerDelay={0.12} className="space-y-6">
              {[
                {
                  name: "Eliza Cloud",
                  desc: "400+ agents, each with scoped spending limits",
                },
                {
                  name: "waifu.fun",
                  desc: "Character agents with per-interaction micro-payments",
                },
                {
                  name: "Your platform",
                  desc: "Any agent framework. Any chain. Any scale.",
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
            Agent wallet infrastructure. Built for Synthesis 2026.
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
            href="https://www.synthesis.fun"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text transition-colors"
          >
            Synthesis Hackathon
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
      <Footer />
    </main>
  );
}
