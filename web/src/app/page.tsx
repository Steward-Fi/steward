"use client";

import { motion, useScroll, useTransform } from "framer-motion";
import Image from "next/image";
import { useRef } from "react";
import { CodeBlock } from "@/components/code-block";
import { Reveal, StaggerContainer, StaggerItem } from "@/components/motion-wrapper";
import { Nav } from "@/components/nav";

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
    <section
      ref={ref}
      className="relative min-h-[88vh] lg:min-h-screen flex items-center px-6 md:px-10 pt-28 pb-20 lg:pb-16 overflow-hidden"
    >
      {/* Grid lines background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-[20%] w-px h-full bg-border-subtle opacity-40" />
        <div className="absolute top-0 left-[40%] w-px h-full bg-border-subtle opacity-20" />
        <div className="absolute top-0 left-[70%] w-px h-full bg-border-subtle opacity-30" />
        <div className="absolute top-[30%] left-0 w-full h-px bg-border-subtle opacity-20" />
        <div className="absolute top-[60%] left-0 w-full h-px bg-border-subtle opacity-15" />
      </div>

      {/* Accent glow */}
      <div className="absolute top-1/3 left-1/4 w-[600px] h-[600px] rounded-full pointer-events-none opacity-[0.07] blur-[120px] bg-[oklch(0.75_0.15_55)]" />

      {/* Compass star watermark */}
      <div className="absolute top-1/2 right-[4%] -translate-y-1/2 opacity-[0.04] pointer-events-none hidden lg:block">
        <Image src="/logo.png" alt="" width={620} height={620} className="w-[520px] h-[520px]" />
      </div>

      <motion.div style={{ opacity, y }} className="relative max-w-[1400px] mx-auto w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          {/* Left: headline */}
          <div className="lg:col-span-7">
            <div
              className="hero-rise inline-flex items-center gap-2 mb-7 border border-border rounded-full pl-1.5 pr-3.5 py-1"
              style={{ animationDelay: "0.1s" }}
            >
              <span className="text-[10px] font-mono uppercase tracking-wider bg-[oklch(0.2_0.04_55)] text-[oklch(0.82_0.14_55)] px-2 py-0.5 rounded-full">
                MIT
              </span>
              <span className="text-xs text-text-secondary">Open source, self-hostable</span>
            </div>

            <h1
              className="hero-rise font-display text-hero-landing font-extrabold leading-[0.9] tracking-[-0.035em] text-balance"
              style={{ animationDelay: "0.2s" }}
            >
              Wallets and policy for
              <br />
              <span className="text-[oklch(0.78_0.15_55)]">humans and agents.</span>
            </h1>

            <p
              className="hero-rise mt-8 text-lg text-text-secondary max-w-xl leading-relaxed text-pretty"
              style={{ animationDelay: "0.38s" }}
            >
              Embedded wallets, custody, and spend policy in one rail. Self-hostable, open source,
              and free of per-transaction tolls. The infrastructure Privy should have been, owned by
              you instead of rented.
            </p>

            <div
              className="hero-rise mt-10 flex flex-wrap items-center gap-4"
              style={{ animationDelay: "0.52s" }}
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

            <div
              className="hero-fade mt-12 flex flex-wrap items-center gap-x-6 gap-y-2.5 text-sm"
              style={{ animationDelay: "0.68s" }}
            >
              <span className="text-xs uppercase tracking-wider text-text-tertiary font-mono">
                The rail under
              </span>
              <span className="text-text font-medium">Waifu</span>
              <span className="w-px h-3.5 bg-border" />
              <span className="text-text font-medium">Consumer apps</span>
              <span className="w-px h-3.5 bg-border" />
              <span className="text-text font-medium">Tokenized assets</span>
            </div>
          </div>

          {/* Right: compact code preview */}
          <div
            className="hero-rise lg:col-span-5 hidden lg:block"
            style={{ animationDelay: "0.5s" }}
          >
            <div className="border border-border bg-bg-elevated rounded-sm shadow-[0_24px_80px_-20px_rgba(0,0,0,0.7)]">
              <CodeBlock
                filename="agent.ts"
                language="typescript"
                typeEffect
                code={`import { StewardClient } from "@stwd/sdk"

const agent = new StewardClient({
  proxy: process.env.STEWARD_PROXY_URL,
  token: process.env.STEWARD_AGENT_TOKEN,
})

// Sign a swap, no private key in memory
await agent.sign({
  to: "0x1inch...",
  value: parseEther("0.5"),
  data: swapCalldata,
})

// Call OpenAI, no API key in env
const res = await agent.proxy("openai", {
  path: "/v1/chat/completions",
  body: { model: "gpt-4o", messages },
})`}
              />
            </div>
          </div>
        </div>
      </motion.div>
    </section>
  );
}

// --- Problem Statement ---
function ProblemSection() {
  const problems = [
    {
      title: "Wallet vendors tax you",
      desc: "Per-user and per-transaction pricing that punishes growth. The more your product works, the more it costs to exist. Prohibitive the moment an agent signs at machine speed.",
    },
    {
      title: "Policy is an afterthought",
      desc: "Custody is solved. Governed custody is not. Spend limits, allowlists, and kill-switches get bolted on, never enforced in the vault itself, where it actually matters.",
    },
    {
      title: "You are a tenant on their stack",
      desc: "Closed source, hosted-only, your keys and data on someone else's infrastructure. When you outgrow them or they change terms, there is no door out.",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="max-w-[1400px] mx-auto">
        <Reveal direction="up">
          <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] max-w-3xl text-balance">
            Wallet infrastructure built for a human-paced world.{" "}
            <span className="text-[oklch(0.78_0.15_55)]">That&apos;s the problem.</span>
          </h2>
        </Reveal>

        <StaggerContainer
          staggerDelay={0.12}
          className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle mt-16 rounded-sm overflow-hidden"
        >
          {problems.map((problem) => (
            <StaggerItem key={problem.title}>
              <div className="bg-bg p-8 md:p-10 h-full">
                <h3 className="font-display text-xl font-bold mb-3 leading-snug">{problem.title}</h3>
                <p className="text-[0.95rem] text-text-secondary leading-relaxed text-pretty">
                  {problem.desc}
                </p>
              </div>
            </StaggerItem>
          ))}
        </StaggerContainer>
      </div>
    </section>
  );
}

// --- vs Privy comparison beat ---
function ComparisonSection() {
  const rows = [
    { feature: "Source", steward: "Open source, MIT", vendor: "Closed, proprietary" },
    { feature: "Hosting", steward: "Self-host or managed", vendor: "Hosted only" },
    { feature: "Pricing", steward: "No per-transaction toll", vendor: "Per-MAU + per-transaction" },
    { feature: "Keys and data", steward: "You own them", vendor: "On their infrastructure" },
    { feature: "Policy engine", steward: "Enforced in the vault", vendor: "Bolted on, if any" },
    { feature: "Agents", steward: "First-class actors", vendor: "Human-paced pricing" },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-start">
          <div className="lg:col-span-4 lg:sticky lg:top-28">
            <Reveal>
              <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
                Own the rail.{" "}
                <span className="text-[oklch(0.78_0.15_55)]">Don&apos;t rent it.</span>
              </h2>
            </Reveal>
            <Reveal delay={0.1}>
              <p className="mt-6 text-text-secondary leading-relaxed max-w-sm text-pretty">
                Closed wallet vendors meter your growth and hold your keys. Steward gives you the
                same embedded wallets and the policy layer they never built, on infrastructure you
                control.
              </p>
            </Reveal>
          </div>

          <div className="lg:col-span-8">
            <Reveal delay={0.1}>
              {/* Desktop / tablet: three-column table. Steward column carries an accent
                  rail + tint so the decision reads in a glance. */}
              <div className="hidden sm:block border border-border rounded-sm overflow-hidden">
                {/* Header */}
                <div className="grid grid-cols-[1.2fr_1fr_1fr] bg-bg-elevated border-b border-border">
                  <div className="px-5 py-4 text-xs uppercase tracking-wider text-text-tertiary font-mono">
                    Capability
                  </div>
                  <div className="px-5 py-4 flex items-center gap-2 border-l border-border-subtle bg-[oklch(0.2_0.04_55)]/40 border-t-2 border-t-[oklch(0.75_0.15_55)]">
                    <Image src="/logo.png" alt="" width={16} height={16} className="w-4 h-4" />
                    <span className="font-display font-bold text-sm">Steward</span>
                  </div>
                  <div className="px-5 py-4 text-sm text-text-tertiary border-l border-border-subtle font-medium">
                    Privy-style vendors
                  </div>
                </div>
                {/* Rows */}
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
                    <div className="px-5 py-4 text-sm text-text-secondary flex items-center">
                      {row.feature}
                    </div>
                    <div className="px-5 py-4 text-sm text-text font-medium flex items-center gap-2.5 border-l border-border-subtle bg-[oklch(0.2_0.04_55)]/40">
                      <span className="text-[oklch(0.8_0.16_55)] flex-shrink-0 font-bold">
                        &#10003;
                      </span>
                      {row.steward}
                    </div>
                    <div className="px-5 py-4 text-sm text-text-tertiary flex items-center gap-2.5 border-l border-border-subtle">
                      <span className="text-text-tertiary flex-shrink-0">&#10005;</span>
                      {row.vendor}
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Mobile: stacked per-capability cards */}
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
                        Privy-style vendors{" "}
                        {row.vendor.charAt(0).toLowerCase() + row.vendor.slice(1)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>
        </div>
      </div>
    </section>
  );
}

// --- Architecture (the one place numbered markers earn it: a real 3-layer stack) ---
function ArchitectureSection() {
  const layers = [
    {
      num: "01",
      label: "Vault",
      detail: "AES-256-GCM encryption at rest",
      items: [
        "Embedded wallets for humans and agents, keys encrypted and never exposed",
        "API credentials stored and injected at the proxy layer",
        "Scoped tokens and self-managed sessions per actor",
      ],
    },
    {
      num: "02",
      label: "Policy Engine",
      detail: "Default deny, explicit allow",
      items: [
        "Spending limits per actor, daily, monthly, and per-transaction",
        "Rate limiting with sliding windows per API, per actor",
        "Approved address and contract allowlists, plus an atomic freeze switch",
      ],
    },
    {
      num: "03",
      label: "Proxy Gateway",
      detail: "The only door out",
      items: [
        "Every outbound call flows through Steward",
        "Credentials injected at the edge, stripped from logs",
        "Full cost attribution and audit trail per actor",
      ],
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <Reveal>
          <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] max-w-3xl text-balance">
            Three layers between your agent{" "}
            <span className="text-[oklch(0.78_0.15_55)]">and the real world.</span>
          </h2>
        </Reveal>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border-subtle mt-16 rounded-sm overflow-hidden">
          {layers.map((layer, i) => (
            <Reveal key={layer.num} delay={i * 0.1} className="bg-bg p-8 md:p-10">
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-sm text-[oklch(0.6_0.1_55)] tracking-tight">
                  {layer.num}
                </span>
                <span className="h-px flex-1 bg-border-subtle translate-y-[-2px]" />
              </div>
              <h3 className="font-display text-xl font-bold mt-5 mb-1">{layer.label}</h3>
              <p className="text-xs text-text-tertiary tracking-wide uppercase mb-5 font-mono">
                {layer.detail}
              </p>
              <ul className="space-y-3">
                {layer.items.map((item) => (
                  <li
                    key={item}
                    className="text-sm text-text-secondary leading-relaxed flex gap-2.5"
                  >
                    <span className="text-[oklch(0.78_0.15_55)] mt-1.5 w-1 h-1 rounded-full bg-current flex-shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </Reveal>
          ))}
        </div>

        {/* Flow diagram */}
        <Reveal delay={0.3} className="mt-14">
          <FlowDiagram />
        </Reveal>
      </div>
    </section>
  );
}

function FlowDiagram() {
  const nodes = [
    { label: "Agent", sub: "SDK / HTTP" },
    { label: "Policy Engine", sub: "Evaluate rules" },
    { label: "Proxy", sub: "Inject credentials" },
    { label: "Vault", sub: "Sign or forward" },
  ];

  return (
    <div className="flex items-center justify-between overflow-x-auto py-6">
      {nodes.map((node, i) => (
        <div key={node.label} className="flex items-center flex-1 min-w-0">
          <motion.div
            initial={{ opacity: 0, scale: 0.92 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{
              delay: i * 0.15,
              duration: 0.4,
              ease: [0.25, 1, 0.5, 1],
            }}
            className="border border-border px-5 py-3 bg-bg-elevated flex-shrink-0 rounded-sm"
          >
            <div className="text-sm font-display font-bold">{node.label}</div>
            <div className="text-xs text-text-tertiary mt-0.5 font-mono">{node.sub}</div>
          </motion.div>
          {i < nodes.length - 1 && (
            <motion.div
              initial={{ opacity: 0, scaleX: 0 }}
              whileInView={{ opacity: 1, scaleX: 1 }}
              viewport={{ once: true }}
              transition={{
                delay: i * 0.15 + 0.2,
                duration: 0.3,
                ease: [0.25, 1, 0.5, 1],
              }}
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
      filename: "sign-transaction.ts",
      code: `import { StewardClient } from "@stwd/sdk"

const steward = new StewardClient({
  baseUrl: process.env.STEWARD_PROXY_URL,
  bearerToken: process.env.STEWARD_AGENT_TOKEN,
})

// Policy-enforced signing
const tx = await steward.signTransaction(agentId, {
  to: "0xDEX...",
  value: "100000000000000000",
})`,
    },
    {
      filename: "api-proxy.ts",
      code: `// Credentials injected, agent never sees the key
const openai = new OpenAI({
  baseURL: \`\${process.env.STEWARD_PROXY_URL}/openai/v1\`,
})

const completion = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "..." }],
})
// Costs tracked, rate-limited, audited`,
    },
    {
      filename: "policies.ts",
      code: `await steward.setPolicies(agentId, [
  { type: "spending-limit",
    config: { maxPerTx: "1e18",
              maxPerDay: "10e18" } },
  { type: "rate-limit",
    config: { window: "1m",
              maxRequests: 60 } },
  { type: "approved-addresses",
    config: { addresses: [
      "0xUniswap...",
      "0xTreasury..."] } },
])`,
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16">
          <div className="lg:col-span-4 lg:sticky lg:top-28 self-start">
            <Reveal>
              <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02]">
                Sign transactions.
                <br />
                Proxy APIs.
                <br />
                <span className="text-[oklch(0.78_0.15_55)]">Enforce everything.</span>
              </h2>
            </Reveal>
            <Reveal delay={0.15}>
              <p className="mt-6 text-text-secondary leading-relaxed text-pretty">
                Create a wallet, attach policy, approve agent spend. A TypeScript SDK for
                policy-checked signing and credential-injected API proxying that works with any agent
                framework.
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

// --- Specs ---
function SpecsSection() {
  const specs = [
    { value: "AES-256-GCM", label: "Encryption at rest" },
    { value: "Default deny", label: "Policy model" },
    { value: "7 EVM + Solana", label: "Chains supported" },
    { value: "< 50ms", label: "Proxy overhead" },
  ];

  return (
    <section className="relative px-6 md:px-10 py-20 md:py-28 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <Reveal>
          <p className="text-text-secondary text-sm mb-8 max-w-2xl">
            Built to enterprise security standards. Audited paths, encrypted at rest, fast enough to
            sit in front of every call.
          </p>
        </Reveal>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-border-subtle rounded-sm overflow-hidden">
          {specs.map((spec, i) => (
            <Reveal key={spec.label} delay={i * 0.1} className="bg-bg p-8 md:p-10 text-center">
              <div className="font-display text-2xl md:text-[1.75rem] font-extrabold tracking-tight">
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

// --- For Platforms ---
function PlatformsSection() {
  const tenants = [
    {
      name: "DeFi & Trading",
      desc: "Trading bots, yield agents, and liquidity managers with enforced spending limits and approved counterparties",
    },
    {
      name: "Apps & Agent Platforms",
      desc: "Consumer apps and agent frameworks that need embedded wallets and secure API access for users and agents alike",
    },
    {
      name: "Treasuries & Rewards",
      desc: "DAO treasuries, perks systems, and micro-payment agents with multi-party approval flows",
    },
    {
      name: "RWA & Settlement",
      desc: "Commodity finance, collateral management, and tokenized asset operations",
    },
  ];

  return (
    <section className="relative px-6 md:px-10 py-24 md:py-32 border-t border-border-subtle">
      <div className="max-w-[1400px] mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16">
          <div className="lg:col-span-5">
            <Reveal>
              <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] text-balance">
                One rail.{" "}
                <span className="text-[oklch(0.78_0.15_55)]">Every actor.</span>
              </h2>
            </Reveal>
            <Reveal delay={0.1}>
              <p className="mt-6 text-lg text-text-secondary leading-relaxed max-w-md text-pretty">
                One Steward instance for thousands of humans and agents across isolated tenants. Each
                tenant gets its own policies, credentials, and webhook endpoints. Self-hosted. No
                per-transaction toll.
              </p>
            </Reveal>
          </div>

          <div className="lg:col-span-7">
            <StaggerContainer
              staggerDelay={0.1}
              className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-border-subtle rounded-sm overflow-hidden"
            >
              {tenants.map((tenant) => (
                <StaggerItem key={tenant.name}>
                  <div className="bg-bg p-7 h-full group hover:bg-bg-elevated transition-colors">
                    <div className="flex items-center gap-2.5 mb-2.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[oklch(0.78_0.15_55)] group-hover:scale-150 transition-transform" />
                      <div className="font-display font-bold text-base">{tenant.name}</div>
                    </div>
                    <div className="text-sm text-text-secondary leading-relaxed text-pretty">
                      {tenant.desc}
                    </div>
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

// --- Open Source / CTA ---
function OpenSourceSection() {
  return (
    <section className="relative px-6 md:px-10 py-32 md:py-44 border-t border-border-subtle overflow-hidden">
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
        <div className="w-[700px] h-[700px] rounded-full opacity-[0.06] blur-[140px] bg-[oklch(0.75_0.15_55)]" />
      </div>
      <div className="relative max-w-[1400px] mx-auto text-center">
        <Reveal>
          <h2 className="font-display text-hero-sm font-extrabold tracking-[-0.02em] leading-[1.02] max-w-3xl mx-auto text-balance">
            Infrastructure you own,{" "}
            <span className="text-[oklch(0.78_0.15_55)]">not a dependency you rent.</span>
          </h2>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="mt-7 text-lg text-text-secondary leading-relaxed max-w-xl mx-auto text-pretty">
            MIT-licensed, self-hostable, and free of per-transaction fees. Everything closed wallet
            vendors are not. Run it on your own infrastructure, keep your keys and your data, and
            never pay a toll on your own growth.
          </p>
        </Reveal>
        <Reveal delay={0.2}>
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
            The open wallet and governance rail for humans and agents.
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
      <ProblemSection />
      <ComparisonSection />
      <ArchitectureSection />
      <SDKSection />
      <SpecsSection />
      <PlatformsSection />
      <OpenSourceSection />
      <Footer />
    </main>
  );
}
