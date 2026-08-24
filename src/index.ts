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
 * SQL-free identity, authentication, and credential management.
 *
 * SQL-specific code (AgentScope, ScopeEngine, pool-dependent column-key
 * operations) lives in the `@abaxxlabs/agents/sql` subpath.
 * Non-SQL consumers (MongoDB, GraphQL, MySQL) can depend on this entry
 * without pulling in pg, libpg-query, or any SQL-specific logic.
 *
 * @example
 * ```typescript
 * // Identity-only consumer (no SQL):
 * import { AgentIdentity } from '@abaxxlabs/agents';
 *
 * // SQL consumer:
 * import { AgentScope } from '@abaxxlabs/agents/sql';
 * ```
 *
 * @module
 */

// ─── Primary class ──────────────────────────────────────────────────

// AgentIdentity — SQL-free identity layer.
export { AgentIdentity } from '#identity/agent-identity.js';
export type { AgentIdentityConfig, AgentIdentityInjections } from '#identity/agent-identity.js';

// ─── Master key ─────────────────────────────────────────────────────

export { asMasterKey } from '#crypto/master-key.js';
export type { MasterKey } from '#crypto/master-key.js';

// ─── Logger ────────────────────────────────────────────────────────

export type { Logger } from './observability/logger.js';
export { defaultLogger, getLogger } from './observability/logger.js';

// ─── Redaction helpers ──────────────────────────────────────────────

export { REDACTED_MASTER_KEY, REDACTED_SIGNER, withRedactedSerialization } from '#crypto/redact.js';

// ─── Migration credential branded types ──────────────────────────

export {
  asTrustedMigrationCredential,
  asVerifiedParentCredential,
} from '#discovery/migration-trust-anchor.js';
export type {
  TrustedMigrationCredential,
  VerifiedParentCredential,
} from '#discovery/migration-trust-anchor.js';

// ─── Types ──────────────────────────────────────────────────────────

export type {
  ScopeMode,
  AgentScopeConfig,
  AuthOptions,
  AuthenticatedSession,
  CreateAgentOptions,
  RegisteredAgent,
  AgentSigner,
  IdSdkInstance,
  IssueCredentialOptions,
  DelegateCredentialOptions,
  CredentialScope,
  AuditRecord,
  AuditEntry,
  VerificationResult,
  DecodedCredential,
} from '#types/index.js';

// ─── Domain types (branded strings) ────────────────────────────────

export type { Did, ColumnName, TableName, Jti, IssuerUrl } from '#types/index.js';
export { asDid, asColumnName, asTableName, asJti, asIssuerUrl } from '#types/index.js';

// ─── Errors ─────────────────────────────────────────────────────────

export {
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  DidResolutionFailedError,
  AuthUnavailableError,
  DbConnectionFailedError,
  SqliteRuntimeUnavailableError,
  AuditWriteFailedError,
  AgentScopeError,
  QueryRejectedError,
  ScopeViolationError,
  CredentialReplayedError,
  TtlExceededError,
  CapabilityRequiresPaidTierError,
  ParentCredentialRequestFailedError,
  DiscoveryEndpointBlockedError,
  KeyRotationFailedError,
  type KeyRotationPhase,
  MasterKeyMismatchError,
  MasterKeyMissingError,
  PrecisionLossError,
} from '#errors/index.js';

export {
  encrypt,
  decrypt,
  generateColumnKey,
  wrapColumnKey,
  unwrapColumnKey,
  decryptRow,
} from '#encryption/index.js';

// ─── Credential verification ────────────────────────────────────────

export { VcVerifier } from '#identity/vc-verifier.js';
export { createJwt, verifyJwtSignature, decodeJwt } from './crypto/jwt.js';

// ─── Audit ──────────────────────────────────────────────────────────

export { AuditLogger, hashAuditRecord } from '#audit/index.js';

// ─── Transport-neutral services ─────────────────────────────────────

export {
  createAgentDirectoryService,
  createAgentToolServices,
  createAuditService,
  createCredentialService,
  createQueryService,
} from '#services/index.js';
export type {
  AgentDirectory,
  AgentDirectoryService,
  AgentToolServices,
  AuditReader,
  AuditService,
  AuditVerifier,
  CredentialDelegator,
  CredentialIssuer,
  CredentialRevoker,
  CredentialService,
  QueryExecutor,
  QueryService,
  ScopedQueryInput,
  ScopedQueryResult,
} from '#services/index.js';

// ─── Transport boundaries ──────────────────────────────────────────

export {
  FixedWindowRateLimiter,
  RateLimitExceededError,
  RequestValidationError,
  SIGN_PAYLOAD_MAX_BYTES,
  SIGN_RATE_LIMIT,
  SIGN_RATE_WINDOW_MS,
  CHALLENGE_RATE_LIMIT,
  CHALLENGE_RATE_WINDOW_MS,
  CREDENTIAL_MINT_OPERATION,
  CREDENTIAL_MINT_RATE_LIMIT,
  CREDENTIAL_MINT_RATE_WINDOW_MS,
  assertExpiresInBound,
  assertUtf8MaxBytes,
  assertWithinRateLimit,
  defaultIdentityRateLimiter,
  mcpToolInputShapes,
  normalizeDomainError,
  rateLimitBucketKey,
  restValidationSchemas,
  toHttpErrorBody,
  toMcpErrorBody,
  validateRequest,
  type NormalizedDomainError,
  type RateLimitCheck,
  type RateLimitDecision,
  type RateLimiter,
  type RateLimitTelemetrySink,
  type RequestSchema,
  type SafeValidationIssue,
} from '#transport/index.js';

// ─── Auth utilities ─────────────────────────────────────────────────

// For most use cases call `AgentIdentity.authenticate()` instead.
export {
  generateDidKey,
  issueCredential,
  issueCredentialFromParent,
  createMockSession,
  createOidcSession,
  createSigner,
  toExternalSigner,
} from '#auth/index.js';

// Generic OIDC — provider-agnostic OAuth.
export { GenericOidcProvider } from '#auth/generic.js';
export { verifyIdTokenSignature } from '#auth/jwks-verify.js';

// Scope Ceiling — session-level authorization bound.
export {
  resolveScopeCeiling,
  resolveScopeCeilingFromClaims,
  unrestrictedCeiling,
  scopeFitsInCeiling,
  assertScopeFitsInCeiling,
  ScopeExceedsCeilingError,
  PolicyViolationError,
  timeOfDayRule,
  type ScopeCeiling,
  type RoleScopeConfig,
  type RequestedScope,
  type IssuanceRule,
  type IssuanceContext,
} from '#auth/ceiling.js';

// ─── Capability ─────────────────────────────────────────────────────

export {
  CapabilityEngine,
  createCapabilityEngine,
  type Capability,
  type CapabilityAction,
  type CapabilityCheckResult,
  type CapabilitySet,
  CapabilityParseError,
  CapabilitySetTooLargeError,
  MAX_CAPABILITY_SET_SIZE,
} from '#capability/index.js';

// ─── Discovery ──────────────────────────────────────────────────────

export {
  LocalTrustAnchorStore,
  createTrustAnchorStore,
  type TrustAnchorStore,
  type TrustAnchor,
  type TrustAnchorSource,
} from '#discovery/trust-anchor.js';

// ─── Identity surface ───────────────────────────────────────────────

// AgentVerifier, OrgBoundary, Keystore, ServerIdentity, Binding.
export * from '#identity/index.js';

// Consumer domain composition (identity-level utility).
export { composeConsumerDomains } from '#identity/org-boundary.js';

// ─── MCP ────────────────────────────────────────────────────────────

// MCP bearer auth — session token authentication for HTTP transport.
export {
  createMcpBearerAuth,
  OVERLAP_WINDOW_SECONDS,
  type McpBearerAuth,
  type McpBearerAuthOptions,
} from '#mcp/auth.js';

// ChallengeStore — HMAC-signed time-based challenges with JTI dedup.
export {
  ChallengeStore,
  DEFAULT_CHALLENGE_TTL_SECONDS,
  MAX_CHALLENGE_TTL_SECONDS,
  MAX_DEDUP_CACHE_SIZE,
  type ChallengeIssueOptions,
  type ChallengeIssueResult,
  type ChallengeConsumeResult,
} from '#mcp/challenge-store.js';

// MCP server — available via @abaxxlabs/agents/mcp subpath.
// Not re-exported here: the server depends on AgentScope (SQL).

// ─── Storage ────────────────────────────────────────────────────────

// Storage backend — abstract persistence layer.
// SQLite backend is at the @abaxxlabs/agents/sqlite subpath.
export {
  createStorageBackend,
  composeStorageBackend,
  createIdentityContext,
  createServerIdentityContext,
  InMemoryRevocationStore,
  InMemorySessionStore,
  deriveSessionMacKey,
  canonicalizeEnvelope,
  computeMac,
  verifyMac,
  HKDF_CONTEXT_SESSION_MAC,
  HKDF_SALT_SESSION_MAC,
  MAX_ENVELOPE_BYTES,
  MAC_BYTES,
  EnvelopeIntegrityError,
  SessionNotPortableError,
  ProviderNotAllowedError,
  EnvelopeTooLargeError,
  type StorageBackend,
  type StorageBackendOptions,
  type PostgresStorageOptions,
  type SqliteStorageOptions,
  type AgentStore,
  type AuditStore,
  type ContextStore,
  type RevocationStore,
  type SessionStore,
  type SessionEnvelope,
  type SessionPutOptions,
  type IdentityContext,
  type AgentRecord,
  type AgentListFilter,
  type ContextEntry,
  type ContextListOptions,
  type AuditQueryFilter,
} from '#storage/index.js';
