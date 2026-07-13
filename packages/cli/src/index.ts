#!/usr/bin/env bun

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { StewardApiClient } from "./api";
import { boolFlag, intFlag, parseArgs, parseJsonFlag, required, stringFlag } from "./args";
import { runDoctor } from "./doctor";
import { type OutputFormat, printResult } from "./format";
import { runInit } from "./init";

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
  steward route add --secret-id ID --agent-id ID --host HOST --path PATH --method METHOD --inject-as header --inject-key KEY
  steward policy set --name NAME --rules '[...]' [--description TEXT] [--agent-id ID]
  steward approvals list|stats|approve|deny ...
  steward audit bundle [--from 1] [--to N] [--out bundle.json] [--verify]

Auth:
  --api-url, --tenant-id, --token, and --platform-key override STEWARD_* env vars.
  Tenant creation uses X-Steward-Platform-Key. Other API-backed commands use Bearer auth.
`;

function createContext(flags: Record<string, string | boolean>): CommandContext {
  return {
    api: new StewardApiClient({
      baseUrl: stringFlag(flags, "api-url"),
      tenantId: stringFlag(flags, "tenant-id"),
      token: stringFlag(flags, "token"),
      platformKey: stringFlag(flags, "platform-key"),
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
