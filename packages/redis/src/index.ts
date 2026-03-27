// @stwd/redis — Redis client, rate limiting, spend tracking, policy caching

export { getRedis, disconnectRedis } from "./client.js";
export { checkRateLimit, getRateLimitStatus, type RateLimitResult } from "./rate-limiter.js";
export {
  recordSpend,
  getSpend,
  checkSpendLimit,
  getSpendByHost,
  type SpendPeriod,
} from "./spend-tracker.js";
export {
  estimateCost,
  getPricingTable,
  isKnownHost,
} from "./cost-estimator.js";
export {
  getCachedPolicies,
  setCachedPolicies,
  invalidateCache,
  invalidateTenantCache,
  type CachedPolicy,
} from "./policy-cache.js";
