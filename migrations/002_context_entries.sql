-- ID++ AgentID — Context Entries Table
-- Phase 2.5: Identity-gated generic document store for StorageBackend.
--
-- Product decision: Chief (and any future consumer) needs an identity-gated
-- document store that lives inside agent-id's trust boundary. Without this,
-- Chief's context graph becomes a side channel — agents communicate outside
-- the credential-scoped, audited path.
--
-- The namespace+key pair forms a composite primary key. Consumers use different
-- namespaces for logical partitioning: Chief uses "context-graph", other
-- consumers use their own namespaces without collision.
--
-- Identity gating: every query includes WHERE owner_did = $callerDid (enforced
-- by PostgresContextStore / SqliteContextStore). The server identity bypass
-- (callerDid === issuerDid) omits the WHERE clause for admin operations.

CREATE TABLE IF NOT EXISTS agent_scope_context (
  namespace TEXT NOT NULL,
  key TEXT NOT NULL,
  value JSONB NOT NULL DEFAULT '{}',
  owner_did TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (namespace, key)
);

-- Index on owner_did for identity-gated list queries.
-- Every non-server list() filters by owner_did — without this index,
-- a table scan is required for every context listing.
CREATE INDEX IF NOT EXISTS idx_context_owner_did ON agent_scope_context(owner_did);

-- Index on namespace for list queries (common access pattern).
CREATE INDEX IF NOT EXISTS idx_context_namespace ON agent_scope_context(namespace);
