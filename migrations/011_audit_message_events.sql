-- Adds agent message event columns to agent_audit (audit-logger v5 schema).
--
-- A message an agent sends or receives is recorded in the same hash-chained
-- audit trail as queries, on the acting agent's instance, signed by the acting
-- agent:
--   event_kind              : 'message' for message events; NULL on older records, which are queries.
--   direction               : 'sent' or 'received', from the acting agent's point of view.
--   counterpart_agent_did   : the peer agent. Verified on a delivered or accepted message; on a
--                             refused send, the recipient as requested. NULL on a refused receipt.
--   counterpart_instance_did: the server DID of the peer's instance, once verified.
--   message_record_id       : the DWN record id of the message.
--   message_digest          : SHA-256 of the sealed ciphertext, hex. The message text is never stored.
--
-- Nullable: query and rejection records leave all of them NULL, and the stores only name these
-- columns when they write a message record. Instances that never write message records keep working
-- before this migration runs.
--
-- Backward compatibility: existing V1/V2/V3/V4 records keep their version and
-- are hashed by their own version logic. hashAuditRecord() includes these
-- fields only for V5 records, so older records remain verifiable unchanged.

ALTER TABLE agent_audit
  ADD COLUMN IF NOT EXISTS event_kind               text,
  ADD COLUMN IF NOT EXISTS direction                text,
  ADD COLUMN IF NOT EXISTS counterpart_agent_did    text,
  ADD COLUMN IF NOT EXISTS counterpart_instance_did text,
  ADD COLUMN IF NOT EXISTS message_record_id        text,
  ADD COLUMN IF NOT EXISTS message_digest           text;

-- Partial: only message records carry a record id, so the index stays small. Building it still
-- scans the whole table and blocks writes meanwhile; on a large table, create it ahead of time
-- with CREATE INDEX CONCURRENTLY.
CREATE INDEX IF NOT EXISTS idx_agent_audit_message
  ON agent_audit(agent_did, message_record_id)
  WHERE message_record_id IS NOT NULL;
