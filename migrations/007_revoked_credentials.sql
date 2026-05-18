-- Migration 007: revoked_credentials
--
--  — makes JTI revocation durable across process restart and coherent
-- across instances. Previously, revocations lived in a process-local Set<string>
-- inside VcVerifier and disappeared on restart — a security-posture gap.
--
-- Hot-path read: isRevoked(jti) called on every VP verification. The store uses
-- an in-process cache (warmed on startup, refreshed every 30s) so the table is
-- only hit on cache misses and concurrent revoke+verify races (D7 row locking).
--
-- Sweep: PostgresRevocationStore.pruneExpired() deletes rows WHERE
--   expires_at < NOW() - interval '30 days'. Background job calls this daily.
--   The 30-day conservative window ensures cross-instance caches have evicted
--   the entry before the DB record disappears.
--
-- Rollback: see demo/hackathon/findings/session-plans/session-3-release/rollback-007.md
--   Emergency: DROP TABLE revoked_credentials (leaf table, no dependents).
--   In-flight revocations revert to in-memory-only until process restart.
--   Row-level locking (D7): migration 007 required for SELECT ... FOR UPDATE on
--   revoked_credentials. If rolled back, PostgresRevocationStore falls back to
--   InMemoryRevocationStore with a warning (NOT the default server behavior —
--   see packages/server/src/index.ts: server fails to start without the table).
--
-- Data retention: 30 days post-expiry. See session-3-release/data-retention.md.
-- GDPR Article 5(1)(e) / SOC 2 CC7.1 alignment: data minimization, storage limitation.
--
-- Schema decision: expires_at is TIMESTAMPTZ (nullable) not an integer epoch.
-- Rationale: consistent with other timestamp columns in this schema; readable
-- in psql; avoids epoch overflow risks. NULL = non-expiring credential (never pruned).
-- Panel consensus: all 4 panelists required expires_at (see 08-synthesis.md).

CREATE TABLE IF NOT EXISTS revoked_credentials (
  jti          TEXT        NOT NULL,
  reason       TEXT,
  revoked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- expires_at: the credential's original exp claim. Nullable for non-expiring creds.
  -- pruneExpired() deletes WHERE expires_at < NOW() - interval '30 days'.
  expires_at   TIMESTAMPTZ,
  PRIMARY KEY (jti)
);

CREATE INDEX IF NOT EXISTS idx_revoked_expires
  ON revoked_credentials (expires_at)
  WHERE expires_at IS NOT NULL;
