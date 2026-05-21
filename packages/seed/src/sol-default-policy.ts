// Sprint 4 Phase 1 Day 3: default policy for the Sol agent.
//
// Idempotent. Safe to call on every Steward dev-mode boot. In production
// this should be invoked once by an operator runbook and then frozen;
// the audit trail then captures any subsequent changes.
//
// The Phase 1 default is intentionally tight:
//   - spending-limit:   $100 / day in USD (price oracle does the math)
//   - venue-allowlist:  ["hyperliquid"]   (no Polymarket / Drift yet)
//   - leverage-cap:     2x                (Sol blows up small)
//
// Worker C wires policy reads into the `/v1/trade/*` route; the policy
// engine then evaluates these rules against every order.
//
// Usage:
//
//   import { seedSolDefaultPolicy } from "@stwd/seed/sol-default-policy";
//   await seedSolDefaultPolicy({ agentId: "sol" });
//
// Or from the CLI:
//
//   bun packages/seed/src/sol-default-policy.ts
//
// Override the agent id with SOL_AGENT_ID env var.

import crypto from "node:crypto";

import { agents, getDb, policies } from "@stwd/db";
import { and, eq } from "drizzle-orm";

export interface SeedSolDefaultPolicyArgs {
  agentId?: string;
  dailyUsd?: number;
  allowedVenues?: string[];
  maxLeverage?: number;
  /**
   * When `true` (the default), pre-existing rows for this agent + type
   * are left untouched so we don't clobber operator overrides. Set to
   * `false` to force a re-seed (intended for tests only).
   */
  preserveExisting?: boolean;
}

export interface SeedSolDefaultPolicyResult {
  agentId: string;
  created: string[]; // policy ids written this run
  preserved: string[]; // policy ids that already existed and were left alone
}

const POLICY_PREFIX = "sol-default";

export async function seedSolDefaultPolicy(
  args: SeedSolDefaultPolicyArgs = {},
): Promise<SeedSolDefaultPolicyResult> {
  const {
    agentId = process.env.SOL_AGENT_ID ?? "sol",
    dailyUsd = 100,
    allowedVenues = ["hyperliquid"],
    maxLeverage = 2,
    preserveExisting = true,
  } = args;

  const db = getDb();

  // Verify the Sol agent row exists; refuse to seed a policy attached to
  // a phantom agent (FK would fail at INSERT but the error message is
  // less helpful than this guard).
  const [agentRow] = await db.select({ id: agents.id }).from(agents).where(eq(agents.id, agentId));
  if (!agentRow) {
    throw new Error(
      `seedSolDefaultPolicy: agent ${agentId} not found. Run @stwd/vault Vault.createAgent first.`,
    );
  }

  const wanted: Array<{ type: PolicyShape["type"]; config: Record<string, unknown> }> = [
    { type: "spending-limit", config: { maxPerDayUsd: dailyUsd } },
    { type: "venue-allowlist", config: { allowedVenues } },
    { type: "leverage-cap", config: { maxLeverage } },
  ];

  const created: string[] = [];
  const preserved: string[] = [];

  for (const policy of wanted) {
    const existing = await db
      .select({ id: policies.id })
      .from(policies)
      .where(and(eq(policies.agentId, agentId), eq(policies.type, policy.type)));

    if (existing.length > 0 && preserveExisting) {
      preserved.push(...existing.map((row) => row.id));
      continue;
    }
    if (existing.length > 0 && !preserveExisting) {
      // Replace: delete then re-insert with a fresh id. We could UPDATE
      // in place, but deleting + inserting also resets `createdAt` which
      // makes audit log timing easier to reason about.
      for (const row of existing) {
        await db.delete(policies).where(eq(policies.id, row.id));
      }
    }

    const id = makePolicyId(agentId, policy.type);
    await db.insert(policies).values({
      id,
      agentId,
      type: policy.type,
      enabled: true,
      config: policy.config,
    });
    created.push(id);
  }

  return { agentId, created, preserved };
}

type PolicyShape = {
  type: "spending-limit" | "venue-allowlist" | "leverage-cap";
};

function makePolicyId(agentId: string, type: string): string {
  // Stable-ish IDs so operators can grep them later, with a short random
  // suffix so re-seeds (under preserveExisting=false) don't collide.
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${POLICY_PREFIX}:${agentId}:${type}:${suffix}`;
}

// CLI entrypoint.
const isEntrypoint =
  typeof process !== "undefined" && process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  seedSolDefaultPolicy()
    .then((result) => {
      console.log(
        JSON.stringify(
          {
            ok: true,
            agentId: result.agentId,
            created: result.created.length,
            preserved: result.preserved.length,
            ids: { created: result.created, preserved: result.preserved },
          },
          null,
          2,
        ),
      );
    })
    .catch((err) => {
      console.error("seedSolDefaultPolicy failed:", err instanceof Error ? err.message : err);
      process.exitCode = 1;
    });
}
