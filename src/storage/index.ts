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
 * SQLite backend is at `@abaxxlabs/agents/sqlite` so better-sqlite3
 * remains optional. Importing this module never triggers a better-sqlite3 import.
 */

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

export {
  EnvelopeIntegrityError,
  SessionNotPortableError,
  ProviderNotAllowedError,
  EnvelopeTooLargeError,
} from './types.js';

export { InMemoryRevocationStore } from './memory/revocation-store.js';

export { InMemorySessionStore } from './memory/session-store.js';

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

export { createIdentityContext, createServerIdentityContext } from './identity-context.js';

export { composeStorageBackend } from './compose.js';

import type { StorageBackend, StorageBackendOptions } from './types.js';

/**
 * Create a StorageBackend from configuration options.
 *
 * SQLite is dynamically imported to keep its native dependency optional.
 * The caller must initialize the returned backend before using its stores.
 *
 * @example
 *   const macKey = await deriveSessionMacKey(masterKey);
 *
 *   // Postgres (production)
 *   const backend = await createStorageBackend({
 *     type: 'postgres',
 *     connectionString: process.env.DATABASE_URL!,
 *     sessionMacKey: macKey,
 *   });
 *
 *   // SQLite
 *   const backend = await createStorageBackend({
 *     type: 'sqlite',
 *     path: './local.db',
 *     sessionMacKey: macKey,
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
      return new PostgresStorageBackend(options, { sessionMacKey: options.sessionMacKey });
    }
    case 'sqlite': {
      const { SqliteStorageBackend } = await import('./sqlite/index.js');
      return SqliteStorageBackend.create(options, { sessionMacKey: options.sessionMacKey });
    }
    default: {
      const exhaustive: never = options;
      throw new Error(`Unknown storage backend type: ${(exhaustive as { type: string }).type}`);
    }
  }
}
