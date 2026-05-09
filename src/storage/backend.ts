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

import type { AgentStore } from './agent-store.js';
import type { AuditStore } from './audit-store.js';
import type { ContextStore } from './context-store.js';
import type { RevocationStore } from './revocation-store.js';
import type { SessionStore } from './session-store.js';

/**
 * StorageBackend — the top-level storage interface for agents.
 *
 * Composed of domain-specific sub-stores. Implementations create all sub-stores
 * from a shared underlying connection (pg.Pool or better-sqlite3 Database).
 *
 * Lifecycle:
 *   const backend = createStorageBackend({ type: 'sqlite', path: ':memory:' });
 *   await backend.initialize();  // create tables, run migrations
 *   // ... use backend.agents, backend.audit, backend.context
 *   await backend.close();       // release connections
 *
 * The initialize() -> use -> close() lifecycle is mandatory. Using sub-stores
 * before initialize() results in missing tables. Using after close() results
 * in connection errors.
 */
export interface StorageBackend {
  /** Agent registry — CRUD for agents. */
  readonly agents: AgentStore;
  /** Append-only audit trail — agent_audit. */
  readonly audit: AuditStore;
  /** Identity-gated document store — agent_context. */
  readonly context: ContextStore;
  /**
   * Durable JTI revocation store — revoked_credentials.
   * Default: InMemoryRevocationStore (zero-config, process-local).
   * Production: PostgresRevocationStore (durable, cross-instance coherent).
   * Local/single-process: SqliteRevocationStore (file-backed).
   */
  readonly revocation: RevocationStore;
  /**
   * Durable session envelope store — sessions.
   * Default: InMemorySessionStore (zero-config, process-local).
   * Production: PostgresSessionStore (durable, multi-instance coherent + 10s cache).
   * Local/single-process: SqliteSessionStore (file-backed, WAL mode).
   */
  readonly sessions: SessionStore;

  /**
   * Initialize the storage backend: create tables, run migrations.
   * Idempotent — safe to call on every startup. Uses CREATE TABLE IF NOT EXISTS
   * and migration tracking to avoid re-running applied migrations.
   */
  initialize(): Promise<void>;

  /**
   * Graceful shutdown. Closes database connections, flushes buffers.
   * After close(), sub-store operations will throw.
   */
  close(): Promise<void>;
}

// ─── Factory Options ────────────────────────────────────────────────────────

/**
 * Configuration for createStorageBackend().
 *
 * Discriminated union on `type`:
 *   - 'postgres': wraps pg.Pool with the connection string. Existing behavior.
 *   - 'sqlite': wraps better-sqlite3 with a file path. ':memory:' for tests.
 */
export type StorageBackendOptions = PostgresStorageOptions | SqliteStorageOptions;

export interface PostgresStorageOptions {
  type: 'postgres';
  /** PostgreSQL connection string (e.g., postgres://user:pass@host:5432/db). */
  connectionString: string;
  /** Connection pool size. Default: 10. */
  poolSize?: number;
  /** HKDF-derived key for session envelope MAC verification. Derive via deriveSessionMacKey(). */
  sessionMacKey: Buffer;
}

export interface SqliteStorageOptions {
  type: 'sqlite';
  /**
   * Path to the SQLite database file.
   * Use ':memory:' for in-memory databases (tests, ephemeral sessions).
   * Use a file path for persistent storage.
   */
  path: string;
  /** HKDF-derived key for session envelope MAC verification. Derive via deriveSessionMacKey(). */
  sessionMacKey: Buffer;
}
