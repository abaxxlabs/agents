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
 * SQL-specific type definitions for `@abaxxlabs/agents/sql`.
 *
 * Types referencing `pg.Pool` live here so the identity entry point
 * never leaks pg into its .d.ts surface.
 */

import type pg from 'pg';
import type { MasterKey } from '../crypto/master-key.js';
import type { StorageBackend } from '../storage/types.js';
import type { Logger } from '../logger.js';
import type {
  AuthOptions,
  AuthenticatedSession,
  CreateAgentOptions,
  RegisteredAgent,
} from '../types/auth.js';
import type { IdSdkInstance } from '../types/id-sdk.js';
import type { AuditRecord } from '../types/audit.js';
import type { VerificationResult } from '../types/verification.js';

// ─── Configuration ───────────────────────────────────────────────

/**
 * Runtime-owned dependencies for `AgentScope.create(config, injections)`.
 *
 * The library never reads `process.env` for key material or persistence wiring.
 * All ambient state arrives here: explicit, caller-supplied, traceable.
 */
export interface AgentScopeInjections {
  /**
   * 32-byte master encryption key. Required. MUST NEVER BE LOGGED.
   *
   * Brand prevents assignment from raw Buffer/string. Source via
   * `resolveMasterKeyFromEnv()` from `@abaxxlabs/agents/bootstrap` or `asMasterKey(buf)`.
   */
  masterKey: MasterKey;

  /**
   * Pre-initialized `StorageBackend`. Caller-owned: `.initialize()` must already
   * have been called; `AgentScope.close()` will NOT close this backend.
   *
   * When omitted, AgentScope builds a `PostgresStorageBackend` from
   * `config.database.connectionString` and owns its lifecycle, but does NOT call
   * `.initialize()` — schema migrations are a deployment concern. No silent
   * in-memory fallback; inject an explicit backend for in-memory sub-stores.
   *
   * **Coherency trade-off (multi-instance deployments):** The default-built
   * backend constructs its `PostgresRevocationStore` with NO `revocationOptions`,
   * so the cross-instance coherency poll is OFF. A credential revoked on instance
   * A stays valid on instances B..N until they restart. Single-instance consumers
   * are unaffected. Multi-instance deployments MUST construct a
   * `PostgresStorageBackend` explicitly, passing
   * `{ revocationOptions: { mode: 'poll', pollIntervalMs: 30_000 } }` (or a
   * tighter interval), and inject it here. See
   * `src/storage/postgres/revocation-store.ts` (`PostgresRevocationStoreOptions`)
   * for the full option surface.
   */
  storage?: StorageBackend;

  /**
   * Platform identity SDK handle. When omitted, the built-in resolver and signer
   * paths are used (sufficient for did:key and demo flows). Preferred integration
   * is `connectIdSdkMcp()` from `@abaxxlabs/agents/id-sdk-mcp`.
   */
  sdk?: IdSdkInstance;

  /**
   * Shared `pg.Pool`. When provided, `AgentScope.close()` does NOT call
   * `pool.end()` — lifecycle stays with the caller.
   */
  pool?: pg.Pool;

  /**
   * Persistent server identity. Pass `initializeServerIdentity()` result so
   * the verifier DID survives restarts. Without it, an ephemeral did:key is
   * generated per process — fine in tests, unsafe in production.
   */
  serverIdentity?: { did: string; publicKey: Uint8Array };

  /** Optional diagnostic logger. Defaults to stderr in the library's existing format. */
  logger?: Logger;
}

// ─── Public API ──────────────────────────────────────────────────

export interface AgentScopeInstance {
  authenticate(options: AuthOptions): Promise<AuthenticatedSession>;
  createAgent(options: CreateAgentOptions): Promise<RegisteredAgent>;
  query(options: QueryOptions): Promise<ScopedResult>;
  verify(auditRecord: AuditRecord): Promise<VerificationResult>;
  close(): Promise<void>;
}

// ─── Query ───────────────────────────────────────────────────────

export interface QueryOptions {
  agent: string;
  credential: string;
  sql: string;
  params?: unknown[];
  /** Target table name — required for column scope enforcement */
  table: string;
  /** Pass multiple credentials for scope union */
  credentials?: string[];
  /**
   * Remote transports set this to require an agent-signed Verifiable
   * Presentation. Local SDK calls may keep the default raw-VC wrapping path for
   * ergonomics because the agent signer is already in-process.
   */
  requirePresentation?: boolean;
  /** AbaxxOne parent instance org ID (parentIssuerDid from session). When present,
   *  the audit record is tagged as V3 with organizational attribution. */
  orgId?: string;
}

export interface ScopedResult {
  rows: Record<string, unknown>[];
  metadata: {
    agent: string;
    owner: string;
    columnsDecrypted: string[];
    columnsEncrypted: string[];
    rowCount: number;
    queryDurationMs: number;
    auditId: string;
  };
}
