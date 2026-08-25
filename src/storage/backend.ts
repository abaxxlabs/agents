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
 * Top-level persistence interface composed of domain-specific stores sharing
 * one backend connection. Call initialize() before use and close() at shutdown.
 */
export interface StorageBackend {
  /** Agent registry. */
  readonly agents: AgentStore;
  /** Append-only audit trail. */
  readonly audit: AuditStore;
  /** Identity-gated document store. */
  readonly context: ContextStore;
  /** JTI revocation store. */
  readonly revocation: RevocationStore;
  /** Session re-establishment envelopes for server/consumer orchestration; AgentScope does not call it. */
  readonly sessions: SessionStore;

  /** Initializes backend-specific schema and lifecycle resources. */
  initialize(): Promise<void>;

  /** Releases backend resources. */
  close(): Promise<void>;
}

/** Configuration for createStorageBackend(). */
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
   * SQLite database path, or ':memory:' for an ephemeral database.
   */
  path: string;
  /** HKDF-derived key for session envelope MAC verification. Derive via deriveSessionMacKey(). */
  sessionMacKey: Buffer;
}
