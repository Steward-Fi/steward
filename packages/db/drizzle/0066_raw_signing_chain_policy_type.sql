-- Privy-parity raw digest chain policy.
--
-- Adds the `raw-signing-chain` value to the policy_type enum so the unsafe
-- raw-digest route can require explicit per-agent chain/curve allowlists before
-- producing signatures for non-EVM protocol compatibility flows.

ALTER TYPE "policy_type" ADD VALUE IF NOT EXISTS 'raw-signing-chain';
