-- Adds delegation provenance columns to agent_audit (audit-logger v4 schema).
--
-- For a query run on a delegated credential, owner_did now holds the root
-- human principal (the registered owner of the querying agent), and the
-- delegating agent is recorded separately:
--   delegator_did      — the delegated credential's issuer (the delegating agent).
--   delegated_grant_id — JTI of the source credential the delegation was granted from.
-- Both are derived from the verified credential chain, never from caller input.
--
-- Nullable: direct (non-delegated) queries leave both NULL.
--
-- Backward compatibility: existing V1/V2/V3 records keep their version and are
-- hashed by their own version logic. hashAuditRecord() includes these fields
-- only for V4 records, so older records remain verifiable unchanged.

ALTER TABLE agent_audit
  ADD COLUMN IF NOT EXISTS delegator_did      text,
  ADD COLUMN IF NOT EXISTS delegated_grant_id text;

CREATE INDEX IF NOT EXISTS idx_audit_delegator_did ON agent_audit(delegator_did);
