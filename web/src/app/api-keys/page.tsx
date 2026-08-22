import Link from "next/link";

export default function ApiKeysPage() {
  return (
    <main className="min-h-screen bg-bg px-6 py-24 text-text">
      <div className="mx-auto max-w-2xl">
        <p className="font-mono text-xs uppercase tracking-wider text-text-tertiary">
          Governed credentials
        </p>
        <h1 className="mt-4 font-display text-4xl font-bold tracking-tight">API keys</h1>
        <p className="mt-5 text-lg leading-relaxed text-text-secondary">
          Store provider credentials behind Steward, then grant agents only the operations they
          need. Raw keys stay outside the agent runtime.
        </p>
        <Link
          href="/dashboard/secrets"
          className="mt-8 inline-flex rounded-sm bg-accent px-5 py-3 text-sm font-semibold text-bg hover:bg-accent-hover"
        >
          Manage governed credentials
        </Link>
      </div>
    </main>
  );
}
