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

export type {
  VerifyOptions,
  VerificationResult,
  DecodedCredential,
} from './verification.js';

export type { AuditRecord, AuditEntry } from './audit.js';

export {
  IDENTITY_MIGRATION_CREDENTIAL,
  type MigrationCredentialClaims,
  type MigrationAuditFields,
} from './migration.js';

export type {
  ColumnKeyRecord,
  EncryptedColumnMeta,
  ColumnKeyMap,
} from './encryption.js';
