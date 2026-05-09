-- Adds version, status, reason, and reason_code columns to agent_audit.
-- Required by audit-logger v3 schema (AuditRecord version field and
-- query rejection logging added in Sprint 2 security hardening).

ALTER TABLE agent_audit
  ADD COLUMN IF NOT EXISTS version     integer DEFAULT 1,
  ADD COLUMN IF NOT EXISTS status      text    DEFAULT 'success',
  ADD COLUMN IF NOT EXISTS reason      text,
  ADD COLUMN IF NOT EXISTS reason_code text;
