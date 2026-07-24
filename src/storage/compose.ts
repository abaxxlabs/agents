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

import type { StorageBackend } from './types.js';

type ComposableKeys = 'agents' | 'audit' | 'context' | 'revocation' | 'sessions';

/**
 * Overrides selected stores while lifecycle methods remain owned by the base.
 * Callers must initialize and close override stores independently.
 * @param base The initialized base backend.
 * @param overrides Stores to replace when their values are defined.
 * @returns A composed backend delegating lifecycle to the base.
 */
export function composeStorageBackend(
  base: StorageBackend,
  overrides: Partial<Pick<StorageBackend, ComposableKeys>>,
): StorageBackend {
  const definedOverrides = Object.fromEntries(
    Object.entries(overrides).filter(([, v]) => v !== undefined),
  ) as Partial<Pick<StorageBackend, ComposableKeys>>;

  return {
    agents: definedOverrides.agents ?? base.agents,
    audit: definedOverrides.audit ?? base.audit,
    context: definedOverrides.context ?? base.context,
    revocation: definedOverrides.revocation ?? base.revocation,
    sessions: definedOverrides.sessions ?? base.sessions,

    initialize: () => base.initialize(),
    close: () => base.close(),
  };
}
