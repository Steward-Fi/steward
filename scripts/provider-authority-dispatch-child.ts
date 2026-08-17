import {
  __setGovernedDispatchHooksForTests,
  dispatchGovernedExecution,
} from "../packages/proxy/src/handlers/governed-execution";

const [intentId, tenantId] = process.argv.slice(2);
if (!intentId || !tenantId) throw new Error("usage: dispatch-child <intent-id> <tenant-id>");

// Operator-only crash-window injection. The upstream response has arrived, but
// the parent deliberately terminates this isolated worker before terminal state
// persistence. No request field or HTTP route can select this hook.
// biome-ignore lint/suspicious/noUndeclaredEnvVars: operator-only child handshake, never a cached task input
if (process.env.STEWARD_SANDBOX_AFTER_UPSTREAM_PAUSE_MS) {
  // biome-ignore lint/suspicious/noUndeclaredEnvVars: validated bounded operator-only fault barrier
  const pause = Number(process.env.STEWARD_SANDBOX_AFTER_UPSTREAM_PAUSE_MS);
  if (!Number.isSafeInteger(pause) || pause < 1 || pause > 120_000) {
    throw new Error("invalid STEWARD_SANDBOX_AFTER_UPSTREAM_PAUSE_MS");
  }
  __setGovernedDispatchHooksForTests({
    afterUpstream: () => {
      process.stdout.write(`${JSON.stringify({ phase: "after_upstream" })}\n`);
      return new Promise((resolve) => setTimeout(resolve, pause));
    },
  });
}

const result = await dispatchGovernedExecution(intentId, tenantId);
process.stdout.write(`${JSON.stringify(result)}\n`);
