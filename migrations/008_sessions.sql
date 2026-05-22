-- Migration 008: sessions
--
-- (Session 5, v0.9.8.0) — makes server session state durable across
-- process restart and coherent across instances. Before this release, sessions
-- lived in a process-local Map<token, {session, createdAt}> in
-- packages/server/src/index.ts and disappeared on restart / were invisible to
-- peer instances behind a load balancer.
--
-- What is stored: a re-establishment envelope (see ISessionStore +
-- SessionEnvelope in src/storage/types.ts). NOT the live AuthenticatedSession
-- object — that holds closures over verifier/sdk/parentProvider instances
-- which are instance-local by design. Cross-instance hit reconstructs a live
-- session from the envelope + the local instance's verifier/sdk/oidcConfig.
--
-- What is NOT stored (security posture):
--   • humanPrivateKey (raw Ed25519) — non-portable sessions stay instance-local
--     (type-level opt-out enforced in server rehydrate path).
--   • parentAccessToken or refresh tokens (D4/D5) — re-auth-on-miss instead.
--   • derived column keys — never in session state; ScopeEngine concern.
--
-- Envelope integrity (D9): `mac` column holds HMAC-SHA256 over canonical envelope
-- encoding (RFC 8785 / JCS via `canonicalize` npm). MAC key is HKDF-derived from
-- the library master key. Tampered rows detected on get() and return
-- HTTP 401 SESSION_INTEGRITY_FAILED + session.rehydrate_rejected_integrity audit
-- event. See src/storage/envelope-mac.ts for threat model.
--
-- Envelope size cap (D21): 32KB enforced at the application layer on the
-- canonical-encoded byte length. Defense against unbounded oidcGroupClaims
-- from self-hosted Keycloak tenants.
--
-- Hot-path read: getSession(token) is called on every authenticated request.
-- PostgresSessionStore ships with a 10s per-instance read-through cache (D15)
-- to bound Postgres read load. Cache TTL = min(10s, envelope.expiresAt - now);
-- cache is NEVER authoritative on deletion.
--
-- Cross-instance coherency (D6, D16 composition): TTL-only. No poll loop, no
-- LISTEN/NOTIFY, no active invalidation channel. Admin revoke (D16) relies on
-- the 10s cache-TTL window for peer-instance eviction. Sessions can be pruned
-- immediately on expiry — the envelope is not a security control; callers who
-- hit an expired token simply re-authenticate.
--
-- Pruning: PostgresSessionStore.pruneExpired() deletes rows WHERE expires_at
-- < NOW(). Recommended cadence (NF-5): hourly for >1k DAU, daily otherwise.
-- Library does NOT run a background loop; consumer schedules.
--
-- Rollback: see session-5-release/rollback-008.md.
--   Emergency: DROP TABLE sessions (leaf table, no dependents). All active
--   sessions invalidated; users re-authenticate. Loss of in-flight sessions
--   is acceptable because session TTL is 4h — no durable business data is
--   lost.
--
-- Data retention: envelope contains DID + email + OIDC subject = PII under
-- GDPR Article 4(1). Active retention = expires_at (default 4h). Post-expiry
-- grace = prune cadence (default hourly). Aggregate ceiling ~5h.
-- deleteByHumanDid() is the GDPR Article 17 hook.
-- See session-5-release/data-retention.md.

CREATE TABLE IF NOT EXISTS sessions (
  -- Opaque session token. Caller-generated; typically randomUUID().
  -- NOT used in any query outside token lookup — treat as a secret.
  token       TEXT        NOT NULL,
  -- Full re-establishment envelope. See SessionEnvelope in src/storage/types.ts
  -- for field semantics. MAC (below) covers the canonical encoding of this.
  envelope    JSONB       NOT NULL,
  -- HMAC-SHA256 (32 bytes) over RFC 8785 canonical envelope encoding. Verified
  -- on every get(); mismatch rejects re-establishment.
  mac         BYTEA       NOT NULL,
  -- Denormalized from envelope.humanDid for O(log N) deleteByHumanDid (NF-9).
  -- Must equal envelope.humanDid — the MAC over the envelope protects the
  -- envelope's humanDid, not this column; a row-tamper that rewrites ONLY
  -- this column would cause a deleteByHumanDid to silently skip or over-match,
  -- which is a correctness issue for GDPR Article 17 rather than a security
  -- issue (the MAC still protects identity on get()).
  human_did   TEXT        NOT NULL,
  -- Creation time (authoritative). Set by DB NOW() so operators can audit
  -- session age without trusting the envelope's createdAt field.
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Expiry (authoritative). Computed by the app via
  -- `NOW() + make_interval(secs => $ttl)` so the DB clock is the source of
  -- truth for cross-instance coherency. NOT NULL enforced at schema level
  -- per D6: a row without expires_at would be permanently cached.
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (token)
);

-- Index on expires_at for efficient pruneExpired() sweeps and expiry-filtered
-- SELECT in the hot path. Plain btree — no partial index, because all rows
-- have a non-null expires_at (schema constraint).
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- Index on human_did for deleteByHumanDid() (NF-9 / GDPR Article 17).
-- Also supports ad-hoc ops queries like "show me all active sessions for DID X"
-- during incident response.
CREATE INDEX IF NOT EXISTS idx_sessions_human_did ON sessions (human_did);
