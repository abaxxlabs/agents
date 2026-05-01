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

export type { IdentityContext } from './identity-context-types.js';
export type { AgentRecord, AgentListFilter, AgentStore } from './agent-store.js';
export type { AuditQueryFilter, AuditStore } from './audit-store.js';
export type { ContextEntry, ContextListOptions, ContextStore } from './context-store.js';
export type { RevocationStore } from './revocation-store.js';
export type {
  SessionEnvelope,
  SessionPutOptions,
  SessionStore,
} from './session-store.js';
export {
  EnvelopeIntegrityError,
  SessionNotPortableError,
  ProviderNotAllowedError,
  EnvelopeTooLargeError,
} from './session-store.js';
export type {
  StorageBackend,
  StorageBackendOptions,
  PostgresStorageOptions,
  SqliteStorageOptions,
} from './backend.js';
