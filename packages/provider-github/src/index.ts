/**
 * @stwd/provider-github — the GitHub provider-action adapter.
 *
 * Owns the two GitHub operation argument schemas (`github.issue.list`,
 * `github.pr.comment.create`), their canonical action construction over the
 * shared `github.provider-action.v1` profile, the non-authoritative safe summary,
 * and the validated policy-context arguments. It imports the shared
 * canonicalizer; it never re-implements JCS, hashing, or normalization.
 */

export {
  buildGithubAction,
  GITHUB_OPERATION_KEYS,
  type GithubActionBuild,
  type GithubOperationKey,
  isGithubOperationKey,
} from "./operations.js";
