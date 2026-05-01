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
 * Shallow-merge helper for StorageBackend composition.
 *
 * Override individual sub-stores on a base backend without reimplementing the
 * full interface. One level of composition only. Lifecycle methods always
 * delegate to `base` — caller must initialize and close override sub-stores.
 *
 * @example
 *   const base = createStorageBackend({ type: 'postgres', connectionString });
 *   await base.initialize();
 *   const backend = composeStorageBackend(base, { revocation: new InMemoryRevocationStore() });
 *   // backend.revocation → InMemoryRevocationStore; all others → Postgres
 */

import type { StorageBackend } from './types.js';

/**
 * The sub-store keys that can be overridden via composeStorageBackend.
 * Lifecycle methods (initialize, close) are intentionally excluded — they
 * always proxy to base.
 */
type ComposableKeys = 'agents' | 'audit' | 'context' | 'revocation' | 'sessions';

/**
 * Compose a StorageBackend by overriding specific sub-stores on top of a base backend.
 *
 * Only sub-stores with a defined (non-undefined) value in `overrides` replace
 * the corresponding sub-store from `base`. Lifecycle methods always delegate
 * to `base`; the caller is responsible for initializing and closing override
 * sub-stores independently.
 *
 * @param base      The base StorageBackend. Must already be initialized before use.
 * @param overrides A partial set of sub-stores to replace on the returned backend.
 * @returns         A new plain StorageBackend object with the overrides applied.
 */
export function composeStorageBackend(
  base: StorageBackend,
  overrides: Partial<Pick<StorageBackend, ComposableKeys>>,
): StorageBackend {
  // Filter undefined so `{ revocation: undefined }` does not blow away the
  // base revocation store. Only explicitly-provided stores replace base.
  const definedOverrides = Object.fromEntries(
    Object.entries(overrides).filter(([, v]) => v !== undefined),
  ) as Partial<Pick<StorageBackend, ComposableKeys>>;

  return {
    agents: definedOverrides.agents ?? base.agents,
    audit: definedOverrides.audit ?? base.audit,
    context: definedOverrides.context ?? base.context,
    revocation: definedOverrides.revocation ?? base.revocation,
    sessions: definedOverrides.sessions ?? base.sessions,

    // Lifecycle always delegates to base. Override sub-stores must be
    // initialized/closed by the caller.
    initialize: () => base.initialize(),
    close: () => base.close(),
  };
}
