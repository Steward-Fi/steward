-- Guest (ephemeral / anonymous) accounts — Privy parity.
--
-- A guest user has no login credential yet: it can immediately receive a
-- session + wallet/agents and later be upgraded ("linked") into a full account
-- by attaching a verified identity (email/OAuth/wallet) WITHOUT losing its data
-- (the user id and all owned rows — agents, wallets, memberships — carry over).
--
-- `is_guest` marks the account ephemeral; it defaults to false so every
-- existing user row stays a full account. `guest_expires_at` bounds the guest
-- session lifetime: it is NULL for full accounts and for guests it holds the
-- hard expiry after which the session is rejected (enforced server-side in
-- verifySessionToken, independent of the access-token exp). Upgrading flips
-- is_guest -> false and clears guest_expires_at while preserving users.id.
ALTER TABLE "users"
  ADD COLUMN IF NOT EXISTS "is_guest" boolean DEFAULT false NOT NULL;
--> statement-breakpoint
ALTER TABLE "users"
  ADD COLUMN IF NOT EXISTS "guest_expires_at" timestamp with time zone;
--> statement-breakpoint
-- Lets a sweeper find expired guests cheaply; partial so the index only covers
-- live guest rows (full accounts have guest_expires_at IS NULL).
CREATE INDEX IF NOT EXISTS "users_guest_expires_at_idx"
  ON "users" ("guest_expires_at") WHERE "is_guest" = true;
