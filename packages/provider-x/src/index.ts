/**
 * @stwd/provider-x — the X (Twitter) provider-action adapter.
 *
 * Owns the three operation argument schemas (`x.tweet.create`,
 * `x.tweet.delete`, `x.user.me.read`), their canonical action construction over
 * the shared `x.provider-action.v1` profile, the non-authoritative safe summary,
 * and the validated policy-context arguments. It imports the shared X
 * canonicalizer; it never re-implements JCS, hashing, or normalization.
 */

export {
  buildXAction,
  isXOperationKey,
  X_OPERATION_KEYS,
  X_OPERATION_RISK,
  type XActionBuild,
  type XOperationKey,
  type XOperationRisk,
} from "./operations.js";
