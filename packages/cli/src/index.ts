#!/usr/bin/env bun

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { StewardApiClient } from "./api";
import { boolFlag, intFlag, parseArgs, parseJsonFlag, required, stringFlag } from "./args";
import { runDoctor } from "./doctor";
import { type OutputFormat, printResult } from "./format";
import { runInit } from "./init";
import { secretsStoreCommand } from "./secrets-store";

type CommandContext = {
  api: StewardApiClient;
  flags: Record<string, string | boolean>;
  format: OutputFormat;
};

const HELP = `steward CLI

Usage:
  steward init [--env .env] [--force] [--migrate]
  steward doctor [--strict] [--json]
  steward tenant create --id ID --name NAME --api-key KEY
  steward agent create --name NAME [--id ID]
  steward agent token --agent-id ID [--expires-in 24h] [--scopes agent,api:proxy]
  steward secret add --name NAME --value VALUE [--description TEXT]
  steward secrets init [--store DIR]
  steward secrets recipient [--store DIR]
  steward secrets put <path> [--store DIR] [--file F] [--desc TEXT] [--overwrite]   (plaintext via --file or stdin; NEVER a flag)
  steward secrets rotate <path> [--store DIR] [--file F]
  steward secrets list [--store DIR]
  steward secrets rm <path> [--store DIR]
  (sealed age-file store: write + exercise only, NO read-back 'get' by design)
  steward route add --secret-id ID --agent-id ID --host HOST --path PATH --method METHOD --inject-as header --inject-key KEY
  steward policy set --name NAME --rules '[...]' [--description TEXT] [--agent-id ID]
  steward approvals list|stats|approve|deny ...
  steward audit bundle [--from 1] [--to N] [--out bundle.json] [--verify]
  steward provider-action create --workspace-id ID --account-id ID --operation KEY --arguments '{...}' --idempotency-key KEY
  steward provider-action get|approval|case --id ID
  steward provider-action approve|deny --id ID --reason TEXT [--idempotency-key KEY]
  steward provider-action execute --id ID [--idempotency-key KEY]
  steward provider-action evidence --id ID [--out bundle.json] [--verify --fp HEX]

provider-action commands are thin wrappers over the PR2-PR5 governed routes
(convenience only; the authoritative proof is
scripts/provider-authority-golden-path.mjs). No new authority is introduced.

Auth:
  --api-url, --tenant-id, --token, --tenant-key, and --platform-key override
  STEWARD_* env vars (STEWARD_API_URL, STEWARD_TENANT_ID, STEWARD_TOKEN,
  STEWARD_TENANT_KEY, STEWARD_PLATFORM_KEY).
  Tenant creation uses X-Steward-Platform-Key.
  Other API-backed commands prefer a Bearer --token; if none is set they fall
  back to the tenant API key (--tenant-key -> X-Steward-Key), which the API
  treats as an api-key machine credential. This is the non-interactive path the
  golden-path script uses (api-key auth bypasses the human-session MFA step-up).
`;

function createContext(flags: Record<string, string | boolean>): CommandContext {
  return {
    api: new StewardApiClient({
      baseUrl: stringFlag(flags, "api-url"),
      tenantId: stringFlag(flags, "tenant-id"),
      token: stringFlag(flags, "token"),
      platformKey: stringFlag(flags, "platform-key"),
      tenantKey: stringFlag(flags, "tenant-key"),
    }),
    flags,
    format: boolFlag(flags, "json") ? "json" : "pretty",
  };
}

async function tenantCommand(action: string | undefined, ctx: CommandContext) {
  if (action !== "create") throw new Error("Supported tenant command: tenant create");
  const apiKey = required(stringFlag(ctx.flags, "api-key"), "api-key");
  const body = {
    id: required(stringFlag(ctx.flags, "id"), "id"),
    name: required(stringFlag(ctx.flags, "name"), "name"),
    apiKeyHash: apiKey,
    webhookUrl: stringFlag(ctx.flags, "webhook-url"),
    defaultPolicies: parseJsonFlag(ctx.flags, "default-policies", undefined),
  };
  return ctx.api.request("POST", "/tenants", body, { platform: true, tenant: false });
}

async function agentCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "create") {
    return ctx.api.request("POST", "/agents", {
      id: stringFlag(ctx.flags, "id"),
      name: required(stringFlag(ctx.flags, "name"), "name"),
      platformId: stringFlag(ctx.flags, "platform-id"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/agents");
  if (action === "token") {
    const agentId = required(stringFlag(ctx.flags, "agent-id"), "agent-id");
    const scopes = stringFlag(ctx.flags, "scopes")
      ?.split(",")
      .map((scope) => scope.trim())
      .filter(Boolean);
    return ctx.api.request("POST", `/agents/${encodeURIComponent(agentId)}/token`, {
      expiresIn: stringFlag(ctx.flags, "expires-in"),
      scopes,
    });
  }
  throw new Error("Supported agent commands: agent create|list|token");
}

async function secretCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "add") {
    return ctx.api.request("POST", "/secrets", {
      name: required(stringFlag(ctx.flags, "name"), "name"),
      value: required(stringFlag(ctx.flags, "value"), "value"),
      description: stringFlag(ctx.flags, "description"),
      expiresAt: stringFlag(ctx.flags, "expires-at"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/secrets");
  if (action === "rotate") {
    const id = required(stringFlag(ctx.flags, "id"), "id");
    return ctx.api.request("PUT", `/secrets/${encodeURIComponent(id)}`, {
      value: required(stringFlag(ctx.flags, "value"), "value"),
    });
  }
  throw new Error("Supported secret commands: secret add|list|rotate");
}

async function routeCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "add") {
    return ctx.api.request("POST", "/secrets/routes", {
      secretId: required(stringFlag(ctx.flags, "secret-id"), "secret-id"),
      agentId: required(stringFlag(ctx.flags, "agent-id"), "agent-id"),
      hostPattern: required(stringFlag(ctx.flags, "host"), "host"),
      pathPattern: required(stringFlag(ctx.flags, "path"), "path"),
      method: required(stringFlag(ctx.flags, "method"), "method"),
      injectAs: required(stringFlag(ctx.flags, "inject-as"), "inject-as"),
      injectKey: required(stringFlag(ctx.flags, "inject-key"), "inject-key"),
      injectFormat: stringFlag(ctx.flags, "inject-format"),
      priority: intFlag(ctx.flags, "priority"),
      enabled: ctx.flags.enabled === undefined ? undefined : boolFlag(ctx.flags, "enabled"),
    });
  }
  if (action === "list") return ctx.api.request("GET", "/secrets/routes");
  if (action === "delete") {
    const id = required(stringFlag(ctx.flags, "id"), "id");
    return ctx.api.request("DELETE", `/secrets/routes/${encodeURIComponent(id)}`);
  }
  throw new Error("Supported route commands: route add|list|delete");
}

async function policyCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "set") {
    const template = await ctx.api.request<{ id: string }>("POST", "/policies", {
      name: required(stringFlag(ctx.flags, "name"), "name"),
      description: stringFlag(ctx.flags, "description") ?? "",
      rules: parseJsonFlag(ctx.flags, "rules", []),
      isDefault: boolFlag(ctx.flags, "default"),
    });
    const agentId = stringFlag(ctx.flags, "agent-id");
    if (!agentId) return template;
    const assignment = await ctx.api.request(
      "POST",
      `/policies/${encodeURIComponent(template.id)}/assign`,
      {
        agentIds: [agentId],
      },
    );
    return { template, assignment };
  }
  if (action === "list") return ctx.api.request("GET", "/policies");
  throw new Error("Supported policy commands: policy set|list");
}

async function approvalsCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "list") {
    const params = new URLSearchParams();
    if (stringFlag(ctx.flags, "status"))
      params.set("status", stringFlag(ctx.flags, "status") as string);
    if (stringFlag(ctx.flags, "limit"))
      params.set("limit", stringFlag(ctx.flags, "limit") as string);
    return ctx.api.request("GET", `/approvals${params.size ? `?${params}` : ""}`);
  }
  if (action === "stats") return ctx.api.request("GET", "/approvals/stats");
  if (action === "approve") {
    const txId = required(stringFlag(ctx.flags, "tx-id"), "tx-id");
    const result = await ctx.api.request("POST", `/approvals/${encodeURIComponent(txId)}/approve`, {
      comment: stringFlag(ctx.flags, "comment"),
    });
    return {
      result,
      note: "If this is a vault transaction, the API requires execution through POST /vault/:agentId/approve/:txId.",
    };
  }
  if (action === "deny") {
    const txId = required(stringFlag(ctx.flags, "tx-id"), "tx-id");
    return ctx.api.request("POST", `/approvals/${encodeURIComponent(txId)}/deny`, {
      reason: required(stringFlag(ctx.flags, "reason"), "reason"),
    });
  }
  throw new Error("Supported approvals commands: approvals list|stats|approve|deny");
}

async function auditCommand(action: string | undefined, ctx: CommandContext) {
  if (action !== "bundle") throw new Error("Supported audit command: audit bundle");
  const params = new URLSearchParams();
  params.set("from", String(intFlag(ctx.flags, "from") ?? 1));
  const to = intFlag(ctx.flags, "to");
  if (to !== undefined) params.set("to", String(to));
  const bundle = await ctx.api.request("GET", `/audit/bundle?${params}`);
  const out = stringFlag(ctx.flags, "out");
  if (out) writeFileSync(out, JSON.stringify(bundle, null, 2));
  if (boolFlag(ctx.flags, "verify")) {
    if (!out) throw new Error("--verify requires --out so the offline verifier has a file");
    const result = spawnSync("node", ["scripts/verify-evidence-bundle.mjs", out], {
      cwd: process.cwd(),
      stdio: "inherit",
    });
    if (result.status !== 0) throw new Error("Offline audit bundle verification failed");
  }
  return out ? { wrote: out, verified: boolFlag(ctx.flags, "verify"), bundle } : bundle;
}

/**
 * PR6 provider-action command group — thin convenience wrappers over the
 * pre-existing PR2-PR5 governed-provider routes. Distribution is unsettled
 * (§5.4), so these are convenience only: the AUTHORITATIVE proof is
 * `scripts/provider-authority-golden-path.mjs`. No new route or authority is
 * introduced; each subcommand maps 1:1 to an existing route. Consequential
 * writes are gated by the SAME approval/execute lifecycle regardless of caller.
 */
async function providerActionCommand(action: string | undefined, ctx: CommandContext) {
  if (action === "create") {
    // Create a provider action (PR2). The route's strict top-level schema accepts
    // exactly {workspaceId, providerAccountId, operationKey, arguments,
    // idempotencyKey}; the API canonicalizes + digests the arguments and hashes
    // the idempotency key server-side. `--arguments` is the adapter argument JSON
    // (e.g. {owner, repo, pullNumber, body}), NOT a pre-built canonical action.
    return ctx.api.request("POST", "/v2/provider-actions", {
      workspaceId: required(stringFlag(ctx.flags, "workspace-id"), "workspace-id"),
      providerAccountId: required(stringFlag(ctx.flags, "account-id"), "account-id"),
      operationKey: required(stringFlag(ctx.flags, "operation"), "operation"),
      arguments: parseJsonFlag(ctx.flags, "arguments", undefined),
      idempotencyKey: required(stringFlag(ctx.flags, "idempotency-key"), "idempotency-key"),
    });
  }
  const id = () => encodeURIComponent(required(stringFlag(ctx.flags, "id"), "id"));
  if (action === "get") {
    return ctx.api.request("GET", `/v2/provider-actions/${id()}`);
  }
  if (action === "approval") {
    // The approval DETAIL (PR3) — requires a human session + recent MFA.
    return ctx.api.request("GET", `/v2/provider-actions/${id()}/approval`);
  }
  if (action === "approve" || action === "deny") {
    // A typed reason is REQUIRED for BOTH decisions (equal-weight, U4/PR3 §9.2).
    // The route ALSO requires an idempotencyKey (rejects with
    // APPROVAL_FIELD_INVALID otherwise) so a retried decision cannot double-apply.
    const reason = required(stringFlag(ctx.flags, "reason"), "reason");
    const actionId = required(stringFlag(ctx.flags, "id"), "id");
    const idempotencyKey =
      stringFlag(ctx.flags, "idempotency-key") ?? `decide-${action}-${actionId}`.slice(0, 255);
    // Build the decide body with OPTIONAL fields OMITTED (not null): the route's
    // strict schema rejects a `reasonCode: null` via isApprovalReasonCode(null)
    // (only a valid code string, or an ABSENT key, is accepted). Sending null
    // when --reason-code is unset would fail APPROVAL_FIELD_INVALID for the
    // common approve/deny case.
    const decideBody: Record<string, unknown> = {
      decision: action === "approve" ? "approve" : "deny",
      reason,
      expectedVersion: intFlag(ctx.flags, "expected-version"),
      expectedRequestHash: stringFlag(ctx.flags, "expected-request-hash"),
      expectedActionDigest: stringFlag(ctx.flags, "expected-action-digest"),
      idempotencyKey,
    };
    const reasonCode = stringFlag(ctx.flags, "reason-code");
    if (reasonCode !== undefined) decideBody.reasonCode = reasonCode;
    return ctx.api.request("POST", `/v2/provider-actions/${id()}/approval`, decideBody);
  }
  if (action === "execute") {
    // Typed system resume (PR3). Body carries ONLY idempotencyKey; actor/action
    // substitution is rejected server-side (RESUME_ACTOR_SUBSTITUTION_FORBIDDEN).
    const idempotencyKey = stringFlag(ctx.flags, "idempotency-key");
    return ctx.api.request(
      "POST",
      `/v2/provider-actions/${id()}/execute`,
      idempotencyKey ? { idempotencyKey } : undefined,
    );
  }
  if (action === "case") {
    // The case manifest (PR5) — owner/admin + recent MFA.
    return ctx.api.request("GET", `/v2/provider-actions/${id()}/case`);
  }
  if (action === "evidence") {
    // The signed evidence bundle (PR5). Optionally write + offline-verify with a
    // trusted key fingerprint (E7): --out bundle.json [--verify --fp <hex>].
    const bundle = await ctx.api.request("GET", `/v2/provider-actions/${id()}/evidence`);
    const out = stringFlag(ctx.flags, "out");
    if (out) writeFileSync(out, JSON.stringify(bundle, null, 2));
    if (boolFlag(ctx.flags, "verify")) {
      if (!out) throw new Error("--verify requires --out so the offline verifier has a file");
      const fp = stringFlag(ctx.flags, "fp") ?? stringFlag(ctx.flags, "expected-key-fingerprint");
      const args = ["scripts/verify-evidence-bundle.mjs", out];
      // E7 / M09: bind trust to an out-of-band fingerprint. Warn loudly if absent
      // (verifying against the embedded key proves self-consistency ONLY).
      if (fp) args.push("--expected-key-fingerprint", fp);
      else
        console.error(
          "WARNING: no --fp supplied; verifying against the EMBEDDED key proves " +
            "self-consistency only, NOT trust to a known signing root (PR5 E7).",
        );
      const result = spawnSync("node", args, { cwd: process.cwd(), stdio: "inherit" });
      if (result.status !== 0) throw new Error("Offline evidence bundle verification failed");
    }
    return out ? { wrote: out, verified: boolFlag(ctx.flags, "verify"), bundle } : bundle;
  }
  throw new Error(
    "Supported provider-action commands: create|get|approval|approve|deny|execute|case|evidence",
  );
}

async function main(argv: string[]) {
  const parsed = parseArgs(argv);
  const [command, action] = parsed.positional;
  const ctx = createContext(parsed.flags);

  if (!command || command === "help" || boolFlag(parsed.flags, "help")) {
    console.log(HELP);
    return;
  }
  if (command === "init") {
    printResult(
      runInit({
        envPath: stringFlag(parsed.flags, "env"),
        force: boolFlag(parsed.flags, "force"),
        runMigrations: boolFlag(parsed.flags, "migrate"),
        databaseUrl: stringFlag(parsed.flags, "database-url"),
        apiUrl: stringFlag(parsed.flags, "api-url"),
      }),
      ctx.format,
    );
    return;
  }
  if (command === "doctor") {
    printResult(
      await runDoctor({
        strict: boolFlag(parsed.flags, "strict"),
        envPath: stringFlag(parsed.flags, "env"),
      }),
      ctx.format,
    );
    return;
  }

  // `secrets` (plural) = sealed age-file SecretStore (local, no API). Distinct
  // from `secret` (singular) which is the API-backed per-tenant SecretVault.
  // The <path> is the third positional; stash it for the store handler.
  if (command === "secrets") {
    const [, , path] = parsed.positional;
    const flags = { ...parsed.flags, ...(path ? { __path: path } : {}) };
    printResult(await secretsStoreCommand(action, flags), ctx.format);
    return;
  }

  const handlers: Record<
    string,
    (action: string | undefined, ctx: CommandContext) => Promise<unknown>
  > = {
    tenant: tenantCommand,
    agent: agentCommand,
    secret: secretCommand,
    route: routeCommand,
    policy: policyCommand,
    approvals: approvalsCommand,
    audit: auditCommand,
    "provider-action": providerActionCommand,
  };
  const handler = handlers[command];
  if (!handler) throw new Error(`Unknown command '${command}'. Run steward help.`);
  printResult(await handler(action, ctx), ctx.format);
}

if (import.meta.main) {
  main(Bun.argv.slice(2)).catch((error) => {
    console.error(`steward: ${(error as Error).message}`);
    process.exit(1);
  });
}
