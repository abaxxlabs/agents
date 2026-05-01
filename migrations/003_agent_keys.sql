-- Migration 003: Agent key persistence
-- Adds encrypted private key and public key columns to agent registry.
-- Keys are AES-256-GCM wrapped with the master key. Enables agent identity
-- survival across server restarts without re-auth.
-- Nullable: agents created before this migration have no persisted keys.

ALTER TABLE agent_scope_agents
  ADD COLUMN IF NOT EXISTS encrypted_private_key BYTEA,
  ADD COLUMN IF NOT EXISTS public_key BYTEA;
