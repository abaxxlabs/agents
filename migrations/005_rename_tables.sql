-- Agents++ — Table Rename Migration
--
-- Renames agent_scope_* tables to plain descriptive names.
-- Follows monorepo convention: plain names, no service prefix.
-- Coexistence: audit_log = human actions (abaxx-one), agent_audit = agent queries (Agents++).

ALTER TABLE IF EXISTS agent_scope_agents RENAME TO agents;
ALTER TABLE IF EXISTS agent_scope_keys RENAME TO agent_keys;
ALTER TABLE IF EXISTS agent_scope_columns RENAME TO agent_columns;
ALTER TABLE IF EXISTS agent_scope_audit RENAME TO agent_audit;
ALTER TABLE IF EXISTS agent_scope_context RENAME TO agent_context;
ALTER TABLE IF EXISTS agent_scope_did_aliases RENAME TO agent_did_aliases;

-- Recreate audit protection with updated names and error messages
CREATE OR REPLACE FUNCTION agent_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'agent_audit is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION agent_audit_no_truncate()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'agent_audit is append-only: TRUNCATE not allowed';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_immutable ON agent_audit;
CREATE TRIGGER trg_audit_immutable
  BEFORE UPDATE OR DELETE ON agent_audit
  FOR EACH ROW EXECUTE FUNCTION agent_audit_immutable();

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON agent_audit;
CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON agent_audit
  FOR EACH STATEMENT EXECUTE FUNCTION agent_audit_no_truncate();

DROP FUNCTION IF EXISTS agent_scope_audit_immutable();
DROP FUNCTION IF EXISTS agent_scope_audit_no_truncate();
