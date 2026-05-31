-- P-256 asymmetric authorization keys + nested key quorums (Privy parity).
--
-- agent_signers: carry an optional asymmetric request-signing key. Existing
-- HMAC signers keep working unchanged (key_type defaults to 'hmac', public_key
-- stays NULL). When key_type = 'p256', public_key holds the registered
-- secp256r1 public key (base64 SPKI / raw 0x04||X||Y / JWK string) and the
-- authorization-signature middleware verifies request signatures with ECDSA.
ALTER TABLE "agent_signers"
  ADD COLUMN IF NOT EXISTS "key_type" varchar(16) DEFAULT 'hmac' NOT NULL,
  ADD COLUMN IF NOT EXISTS "public_key" text;

-- agent_key_quorums: nested-quorum support. member_signer_ids continues to
-- hold leaf agent_signers.id values; member_quorum_ids holds child
-- agent_key_quorums.id values. A quorum is satisfied iff the count of satisfied
-- members (verified leaf signer OR satisfied child quorum) >= threshold.
-- Recursion is bounded by a hard depth limit + cycle detection in the
-- middleware; both fail closed (deny).
ALTER TABLE "agent_key_quorums"
  ADD COLUMN IF NOT EXISTS "member_quorum_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL;
