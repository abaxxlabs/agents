-- Migration 006: Add org_id to audit records for organizational context.
--
-- Product decision: when agents operate under an AbaxxOne parent instance,
-- audit records must trace back to which organization authorized the agent.
-- orgId is derived from the verified credential's iss field, never from
-- caller-supplied parameters, to prevent audit spoofing.
--
-- Design note: single-org by design. Multi-org membership is supported by
-- AbaxxOne's user_tenants table, but agents indexes on the credential that
-- authorized the current session. If multi-org is needed later, this column
-- becomes the session's active org (not a junction table).
--
-- Backward compatibility: existing V1/V2 records will have NULL org_id.
-- The hash chain is not affected — hashAuditRecord() checks the version
-- field to determine which fields to include. V3 records include orgId
-- in the hash; V1/V2 records do not.
ALTER TABLE agent_audit ADD COLUMN org_id TEXT;
CREATE INDEX idx_audit_org_id ON agent_audit(org_id);
