// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * SQLite schema creation statements and additive migrations.
 * SQLite adaptations from Postgres: TIMESTAMPTZ→TEXT, JSONB→TEXT, BYTEA→BLOB,
 * gen_random_uuid()→app-generated, Postgres triggers→SQLite triggers.
 */

/** Ordered, repeatable schema statements for SqliteStorageBackend.initialize(). */
export const SQLITE_SCHEMA_STATEMENTS: string[] = [
  // WAL with NORMAL synchronization permits concurrent reads and writes.
  'PRAGMA journal_mode = WAL',
  'PRAGMA synchronous = NORMAL',
  'PRAGMA foreign_keys = ON',

  `CREATE TABLE IF NOT EXISTS agents (
    did TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    encrypted_private_key BLOB,
    public_key BLOB,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,

  // Encryption tables provide schema parity; ScopeEngine enforcement is PostgreSQL-only.
  `CREATE TABLE IF NOT EXISTS agent_keys (
    id TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    encrypted_key BLOB NOT NULL,
    algorithm TEXT DEFAULT 'aes-256-gcm',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT,
    UNIQUE(table_name, column_name)
  )`,

  `CREATE TABLE IF NOT EXISTS agent_columns (
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    key_id TEXT REFERENCES agent_keys(id),
    original_type TEXT NOT NULL,
    is_encrypted INTEGER DEFAULT 0,
    PRIMARY KEY (table_name, column_name)
  )`,

  `CREATE TABLE IF NOT EXISTS agent_audit (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    agent_did TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    columns_accessed TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT 'GENESIS',
    signature TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'success',
    reason TEXT,
    reason_code TEXT
  )`,

  `CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
    BEFORE UPDATE ON agent_audit
    BEGIN
      SELECT RAISE(ABORT, 'agent_audit is append-only: UPDATE not allowed');
    END`,

  `CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
    BEFORE DELETE ON agent_audit
    BEGIN
      SELECT RAISE(ABORT, 'agent_audit is append-only: DELETE not allowed');
    END`,

  'CREATE INDEX IF NOT EXISTS idx_audit_agent_did ON agent_audit(agent_did)',
  'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON agent_audit(timestamp)',

  `CREATE TABLE IF NOT EXISTS agent_context (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '{}',
    owner_did TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (namespace, key)
  )`,

  'CREATE INDEX IF NOT EXISTS idx_context_owner_did ON agent_context(owner_did)',
  'CREATE INDEX IF NOT EXISTS idx_context_namespace ON agent_context(namespace)',

  `CREATE TABLE IF NOT EXISTS agent_did_aliases (
    old_did TEXT NOT NULL,
    new_did TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    oidc_subject TEXT,
    oidc_issuer TEXT,
    migrated_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    PRIMARY KEY (old_did, new_did)
  )`,

  'CREATE INDEX IF NOT EXISTS idx_did_aliases_new_did ON agent_did_aliases(new_did)',
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_did_aliases_credential_hash ON agent_did_aliases(credential_hash)',

  `CREATE TABLE IF NOT EXISTS revoked_credentials (
    jti         TEXT        NOT NULL,
    reason      TEXT,
    revoked_at  TEXT        NOT NULL DEFAULT (datetime('now')),
    -- expires_at: the credential's original exp claim (ISO 8601).
    -- NULL for non-expiring credentials (never pruned).
    -- pruneExpired() deletes WHERE expires_at < cutoff.
    expires_at  TEXT,
    PRIMARY KEY (jti)
  )`,

  'CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_credentials(expires_at)',

  `CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT    NOT NULL,
    envelope    TEXT    NOT NULL,
    mac         BLOB    NOT NULL,
    human_did   TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (token)
  )`,

  'CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_human_did ON sessions(human_did)',
];

/** Additive statements run after schema creation for existing databases. */
export const SQLITE_MIGRATIONS: string[] = [
  `ALTER TABLE agents ADD COLUMN encrypted_private_key BLOB`,
  `ALTER TABLE agents ADD COLUMN public_key BLOB`,
  // org_id: nullable — free-tier agents have no org context.
  // Derived from the verified credential's iss; never accepted from caller input.
  `ALTER TABLE agent_audit ADD COLUMN org_id TEXT`,
  `CREATE INDEX IF NOT EXISTS idx_agent_audit_org_id ON agent_audit(org_id)`,
  // v3 audit columns — mirror Postgres migration 009. Without these, records lose
  // version/status/reason on read-back and hash under the wrong hashAuditRecord branch.
  `ALTER TABLE agent_audit ADD COLUMN version INTEGER DEFAULT 1`,
  `ALTER TABLE agent_audit ADD COLUMN status TEXT DEFAULT 'success'`,
  `ALTER TABLE agent_audit ADD COLUMN reason TEXT`,
  `ALTER TABLE agent_audit ADD COLUMN reason_code TEXT`,
];
