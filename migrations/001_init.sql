-- ID++ AgentID — Database Schema
-- Phase A: Demo harness tables

-- Agent registry
CREATE TABLE IF NOT EXISTS agent_scope_agents (
  did TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_did TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Column encryption keys (wrapped with master key)
CREATE TABLE IF NOT EXISTS agent_scope_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  encrypted_key BYTEA NOT NULL,
  algorithm TEXT DEFAULT 'aes-256-gcm',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  rotated_at TIMESTAMPTZ,
  UNIQUE(table_name, column_name)
);

-- Column encryption metadata
CREATE TABLE IF NOT EXISTS agent_scope_columns (
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  key_id UUID REFERENCES agent_scope_keys(id),
  original_type TEXT NOT NULL,
  is_encrypted BOOLEAN DEFAULT false,
  PRIMARY KEY (table_name, column_name)
);

-- Signed audit trail (append-only, hash-chained)
CREATE TABLE IF NOT EXISTS agent_scope_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  agent_did TEXT NOT NULL,
  owner_did TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  columns_accessed JSONB NOT NULL,
  row_count INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  previous_hash TEXT NOT NULL DEFAULT 'GENESIS',
  signature TEXT NOT NULL
);

-- A-2: Enforce append-only on audit table via trigger
CREATE OR REPLACE FUNCTION agent_scope_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'agent_scope_audit is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_immutable ON agent_scope_audit;
CREATE TRIGGER trg_audit_immutable
  BEFORE UPDATE OR DELETE ON agent_scope_audit
  FOR EACH ROW EXECUTE FUNCTION agent_scope_audit_immutable();

-- A-2b: Block TRUNCATE on audit table (FOR EACH ROW triggers don't fire on TRUNCATE)
CREATE OR REPLACE FUNCTION agent_scope_audit_no_truncate()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'agent_scope_audit is append-only: TRUNCATE not allowed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON agent_scope_audit;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON agent_scope_audit
  FOR EACH STATEMENT EXECUTE FUNCTION agent_scope_audit_no_truncate();

-- Indexes
CREATE INDEX IF NOT EXISTS idx_audit_agent_did ON agent_scope_audit(agent_did);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON agent_scope_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_keys_table_column ON agent_scope_keys(table_name, column_name);
