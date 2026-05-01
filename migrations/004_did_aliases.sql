-- Migration 004: DID alias table for identity migration.
--
-- Product decision: when a user upgrades from free tier (did:key) to AbaxxOne
-- (did:dht), their DID changes. This table records the mapping so the system
-- can resolve both DIDs to the same identity during the grace period and
-- maintain audit trail continuity after migration completes.
--
-- Architectural decision: alias resolution for context store and agent store
-- is handled via atomic UPDATE in the migration transaction (not query-time
-- alias expansion). This table exists for: (1) grace period DID comparison
-- in the scope engine and vc-verifier, (2) audit trail alias resolution at
-- query time, and (3) idempotency checks (prevent double migration).
--
-- Security decision (panel review Finding #1): alias resolution must NOT be
-- application-level DID rewriting. The context store's security invariant
-- ("database enforces the boundary") is preserved by UPDATE-ing owner_did
-- in the migration transaction, not by expanding WHERE clauses at runtime.
--
-- The credential_hash column enables idempotency: the same migration credential
-- presented twice is a no-op (panel review Finding #10).
--
-- The expires_at column enforces grace period bounds (panel review Finding #12).
-- After expiry, alias-aware DID comparison stops honoring the old DID.

CREATE TABLE IF NOT EXISTS agent_scope_did_aliases (
  old_did TEXT NOT NULL,
  new_did TEXT NOT NULL,
  credential_hash TEXT NOT NULL,
  oidc_subject TEXT,
  oidc_issuer TEXT,
  migrated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (old_did, new_did)
);

-- Lookup by new DID (reverse resolution for audit queries).
CREATE INDEX IF NOT EXISTS idx_did_aliases_new_did
  ON agent_scope_did_aliases(new_did);

-- Idempotency: check if a migration credential has already been processed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_did_aliases_credential_hash
  ON agent_scope_did_aliases(credential_hash);
