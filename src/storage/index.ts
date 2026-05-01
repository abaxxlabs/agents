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
 * StorageBackend public API barrel.
 *
 * SQLite backend is at `@abaxxlabs/agents/sqlite` (subpath) so better-sqlite3
 * remains optional. Importing this module never triggers a better-sqlite3 import.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type {
  StorageBackend,
  StorageBackendOptions,
  PostgresStorageOptions,
  SqliteStorageOptions,
  AgentStore,
  AuditStore,
  ContextStore,
  RevocationStore,
  SessionStore,
  SessionEnvelope,
  SessionPutOptions,
  IdentityContext,
  AgentRecord,
  AgentListFilter,
  ContextEntry,
  ContextListOptions,
  AuditQueryFilter,
} from './types.js';

// SessionStore error classes
export {
  EnvelopeIntegrityError,
  SessionNotPortableError,
  ProviderNotAllowedError,
  EnvelopeTooLargeError,
} from './types.js';

// Exported so consumers can pass their own instance (e.g. tests that stub
// revocation behavior).
export { InMemoryRevocationStore } from './memory/revocation-store.js';

// Exported so consumers can construct the default session store directly
// without going through createStorageBackend.
export { InMemorySessionStore } from './memory/session-store.js';

// Envelope-MAC primitive + context constants. Subsystems deriving keys from
// the master key MUST use the exported HKDF context strings rather than
// reverse-engineering them.
export {
  deriveSessionMacKey,
  canonicalizeEnvelope,
  computeMac,
  verifyMac,
  HKDF_CONTEXT_SESSION_MAC,
  HKDF_SALT_SESSION_MAC,
  MAX_ENVELOPE_BYTES,
  MAC_BYTES,
} from './envelope-mac.js';

// ─── Factories ──────────────────────────────────────────────────────────────────

export { createIdentityContext, createServerIdentityContext } from './identity-context.js';

// StorageBackend composition helper. Lets consumers swap individual sub-stores
// onto a base backend without re-implementing the full StorageBackend interface.
export { composeStorageBackend } from './compose.js';

// ─── StorageBackend factory ─────────────────────────────────────────────────────

import type { StorageBackend, StorageBackendOptions } from './types.js';

/**
 * Create a StorageBackend from configuration options.
 *
 * For 'postgres': creates a PostgresStorageBackend wrapping a new pg.Pool.
 * For 'sqlite': dynamically imports the SQLite module (requires better-sqlite3
 * as a peer dependency — throws a clear error if not installed).
 *
 * The returned backend is NOT initialized — caller must await backend.initialize()
 * before using sub-stores.
 *
 * @example
 *   // Postgres (production)
 *   const backend = await createStorageBackend({
 *     type: 'postgres',
 *     connectionString: process.env.DATABASE_URL!,
 *   });
 *
 *   // SQLite
 *   const backend = await createStorageBackend({
 *     type: 'sqlite',
 *     path: './local.db',
 *   });
 *
 *   await backend.initialize();
 */
export async function createStorageBackend(
  options: StorageBackendOptions,
): Promise<StorageBackend> {
  switch (options.type) {
    case 'postgres': {
      const { PostgresStorageBackend } = await import('./postgres/index.js');
      return new PostgresStorageBackend(options);
    }
    case 'sqlite': {
      const { SqliteStorageBackend } = await import('./sqlite/index.js');
      return SqliteStorageBackend.create(
        options,
        options.sessionMacKey ? { sessionMacKey: options.sessionMacKey } : undefined,
      );
    }
    default: {
      // Exhaustiveness check — TypeScript should catch this at compile time,
      // but runtime guard for JavaScript callers or type-cast bypasses.
      const exhaustive: never = options;
      throw new Error(`Unknown storage backend type: ${(exhaustive as { type: string }).type}`);
    }
  }
}
