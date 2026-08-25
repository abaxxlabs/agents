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
 * PostgreSQL-specific surface: AgentScope, ScopeEngine, and pool-dependent
 * column-key management. Non-SQL consumers import from `@abaxxlabs/agents`
 * to avoid pulling in pg or libpg-query.
 *
 * @example
 * ```typescript
 * import { AgentScope } from '@abaxxlabs/agents/sql';
 * import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
 *
 * const scope = await AgentScope.create(
 *   { database: { connectionString: process.env.DATABASE_URL! } },
 *   { masterKey: resolveMasterKeyFromEnv() },
 * );
 * ```
 *
 * @module
 */

export { AgentScope } from './agent-scope.js';

export type { ScopeMode } from './scope-engine.js';
export { ScopeEngine } from './scope-engine.js';

export {
  loadColumnKeys,
  registerColumn,
  encryptColumnInPlace,
  rotateColumnKey,
  rewrapColumnKey,
  verifyAllColumnKeys,
} from './column-keys.js';
export type { LoadColumnKeysResult } from './column-keys.js';

// AgentScopeConfig stays in the shared types module (pg-free).
export type { AgentScopeConfig } from '#types/config.js';

// SQL-specific types that reference pg live in sql/types.ts.
export type {
  AgentScopeInjections,
  AgentScopeInstance,
  QueryOptions,
  ScopedResult,
} from './types.js';

// Re-export all errors so instanceof checks work across subpaths.
export {
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  DidResolutionFailedError,
  AuthUnavailableError,
  DbConnectionFailedError,
  AuditWriteFailedError,
  AgentScopeError,
  QueryRejectedError,
  ScopeViolationError,
  CredentialReplayedError,
  CapabilityRequiresPaidTierError,
  ParentCredentialRequestFailedError,
  KeyRotationFailedError,
  type KeyRotationPhase,
  MasterKeyMismatchError,
  MasterKeyMissingError,
} from '#errors/index.js';
