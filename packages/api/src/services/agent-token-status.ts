import { getRedisClient } from "../middleware/redis";

const TOKEN_STATUS_KEY_PREFIX = "agent-token-status";
const LAST_OBSERVED_TTL_SECONDS = 7 * 24 * 60 * 60;

type AgentTokenStatus = {
  agentId: string;
  exp: number;
  observedAt: number;
};

const memoryLastObserved = new Map<string, AgentTokenStatus>();

function statusKey(agentId: string): string {
  return `${TOKEN_STATUS_KEY_PREFIX}:${agentId}`;
}

export async function recordAgentTokenExp(agentId: string, exp: number): Promise<void> {
  if (!Number.isFinite(exp)) return;

  const status: AgentTokenStatus = {
    agentId,
    exp,
    observedAt: Math.floor(Date.now() / 1000),
  };
  memoryLastObserved.set(agentId, status);

  const redis = getRedisClient();
  if (!redis) return;

  try {
    await redis.setex(statusKey(agentId), LAST_OBSERVED_TTL_SECONDS, JSON.stringify(status));
  } catch (error) {
    console.warn("[steward:agent-token] failed to record token status in redis", {
      agentId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

export async function getAgentTokenStatus(agentId: string): Promise<AgentTokenStatus | null> {
  const redis = getRedisClient();
  if (redis) {
    try {
      const raw = await redis.get(statusKey(agentId));
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<AgentTokenStatus>;
        if (parsed.agentId === agentId && typeof parsed.exp === "number") {
          return {
            agentId,
            exp: parsed.exp,
            observedAt:
              typeof parsed.observedAt === "number"
                ? parsed.observedAt
                : Math.floor(Date.now() / 1000),
          };
        }
      }
    } catch (error) {
      console.warn("[steward:agent-token] failed to read token status from redis", {
        agentId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return memoryLastObserved.get(agentId) ?? null;
}

export function clearAgentTokenStatusForTests(): void {
  memoryLastObserved.clear();
}
