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

export type { Did, ColumnName, TableName, Jti, IssuerUrl } from './domain.js';
export { asDid, asColumnName, asTableName, asJti, asIssuerUrl } from './domain.js';

export type { IdSdkInstance, IdSdkVcApi, IdSdkDidApi } from './id-sdk.js';

export type { ScopeMode, AgentScopeConfig } from './config.js';

export type {
  AuthOptions,
  AuthenticatedSession,
  CreateAgentOptions,
  AgentSigner,
  RegisteredAgent,
} from './auth.js';

export type {
  IssueCredentialOptions,
  CredentialScope,
  DelegateCredentialOptions,
} from './credential.js';

export type { VerifyOptions, VerificationResult, DecodedCredential } from './verification.js';

export type { AuditRecord, AuditEntry } from './audit.js';

export {
  IDENTITY_MIGRATION_CREDENTIAL,
  type MigrationCredentialClaims,
  type MigrationAuditFields,
} from './migration.js';

export type { ColumnKeyRecord, EncryptedColumnMeta, ColumnKeyMap } from './encryption.js';
