// @stwd/redis — Redis client, rate limiting, spend tracking, policy caching

export {
  type AggregationEvent,
  type AggregationMetricFamily,
  type AggregationScope,
  type AggregationSnapshotQuery,
  getAggregationSnapshot,
  recordAggregationEvent,
} from "./aggregation-tracker.js";
export {
  assertRedisUrlTls,
  assertUpstashRestUrlTls,
  createRedisClient,
  disconnectRedis,
  getRedis,
  getRedisDriver,
  type IoredisLike,
  type RedisClientEnvironment,
  type RedisDriver,
  setRedisClientResolverForRuntime,
} from "./client.js";
export {
  estimateCost,
  getPricingTable,
  isKnownHost,
} from "./cost-estimator.js";
export {
  type CumulativeSpendBatchGroup,
  type CumulativeSpendBatchResult,
  type CumulativeSpendCap,
  type CumulativeSpendScope,
  type CumulativeSpendSnapshot,
  type CumulativeSpendStream,
  getCumulativeSpendSum,
  getWindowedInvokeCount,
  type ReserveCumulativeSpendInput,
  type ReserveCumulativeSpendResult,
  releaseCumulativeSpend,
  releaseLegacyCumulativeSpendAfterCutover,
  releaseLegacyWindowedInvokeAfterCutover,
  releaseWindowedInvoke,
  reserveCumulativeSpend,
  reserveCumulativeSpendBatch,
  reserveWindowedInvoke,
  settleCumulativeSpend,
} from "./cumulative-spend-tracker.js";
export {
  type CachedPolicy,
  getCachedPolicies,
  invalidateCache,
  invalidateTenantCache,
  setCachedPolicies,
} from "./policy-cache.js";
export {
  checkRateLimit,
  exerciseRateLimitReadiness,
  getRateLimitStatus,
  type RateLimitResult,
  rateLimitBucketKey,
} from "./rate-limiter.js";
export {
  checkSpendLimit,
  getSpend,
  getSpendByHost,
  type IdempotentSpendReservationResult,
  recordSpend,
  reserveDailySpendIdempotently,
  reserveSpend,
  type SpendLimitSnapshot,
  type SpendPeriod,
  type SpendRecordOptions,
  type SpendReservation,
  settleReservedSpend,
} from "./spend-tracker.js";
export type { IoredisPipelineLike } from "./upstash-adapter.js";
export { createUpstashIoredisAdapter } from "./upstash-adapter.js";
