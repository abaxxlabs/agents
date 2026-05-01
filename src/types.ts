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
 * Agents++ — Type Definitions
 *
 * All interfaces from the Application Design Document v2.
 * These types are the contract between modules and the public API.
 */

// ─── Scope Mode ─────────────────────────────────────────────────

/**
 * Controls how aggressively the projection boundary enforces column access.
 * Defined here (not in sql/) so the identity-only entry has no transitive
 * dependency on pg or libpg-query.
 */
export type ScopeMode = 'projection';

// ─── Configuration ───────────────────────────────────────────────

export interface AgentScopeConfig {
  database: {
    connectionString: string;
    poolSize?: number; // default: 10
  };

  /**
   * AbaxxOne enterprise OIDC provider.
   *
   * Optional — generic OIDC providers can be used instead via `oidc`.
   * At least one of `abaxxOne` or `oidc` must be present unless `devMode: true`
   * is also set (which enables the mock OIDC path).
   *
   * Optional — generic OIDC providers can be used instead via `oidc`.
   */
  abaxxOne?: {
    tenantUrl: string;
    clientId: string;
    clientSecret?: string; // optional for public clients (PKCE)
  };

  /**
   * Generic OIDC provider configuration.
   *
   * Use this for any standard OAuth 2.0 / OIDC provider:
   * Google Workspace, Azure AD, Okta, Auth0, Keycloak, etc.
   *
   * When set, GenericOidcProvider is used instead of AbaxxOneOidcProvider.
   * The humanDid is derived deterministically from issuerUrl + sub.
   * See GenericOidcProvider for derivation details.
   *
   * Cannot be set at the same time as abaxxOne — use one or the other.
   */
  oidc?: {
    issuerUrl: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    scopes?: string[]; // default: ['openid', 'profile', 'email']
  };
  /**
   * Column-encryption configuration.
   *
   * The master key is NOT on this config. It is supplied through the second
   * parameter of `AgentScope.create(config, injections)` as
   * `injections.masterKey: MasterKey`. Removed from the type so libraries
   * cannot accidentally accept key material from a config blob that may have
   * been read off disk, logged, or sent over the wire. Consumers source the
   * key through `resolveMasterKeyFromEnv()` (from `@abaxxlabs/agents/bootstrap`),
   * an HSM/KMS, or any other mechanism, and pass the resulting Buffer
   * directly to `AgentScope.create` via `injections`.
   */
  encryption?: {
    algorithm?: 'aes-256-gcm'; // only option in v1
    columns?: string[]; // e.g., ['patients.dob', 'patients.diagnosis']
  };
  audit?: {
    enabled?: boolean; // default: true
  };
  credential?: {
    maxTtl?: string; // default: '24h'
    clockSkew?: string; // default: '30s'
  };
  did?: {
    resolverCacheTtl?: string; // default: '5m'
  };
  log?: {
    level?: 'debug' | 'info' | 'warn' | 'error'; // default: 'info'
  };
  /**
   * Controls projection-boundary enforcement. 'projection' (default and only
   * option) rejects queries referencing ANY column not in the credential's scope.
   */
  scopeMode?: ScopeMode;

  /**
   * Org boundary configuration.
   *
   * `extraConsumerDomains` extends the built-in consumer-domain registry that
   * `OrgBoundary` and `GenericOidcProvider` use to decide whether an email
   * address represents a consumer (no enterprise org) or an enterprise org.
   * Consumer domains (gmail.com, outlook.com, yahoo.com, etc.) are
   * security-posture decisions: an agent running as `alice@gmail.com` cannot
   * prove org membership, so verifiers must reject org-scoped requests.
   *
   * The library does not read `process.env` for this signal — consumers
   * bridge from env at their own boundary if needed. Centralizing on a single
   * config field avoids the inconsistent-boundary risk of having multiple
   * independent read sites.
   *
   * Domains are case-insensitive (lowercased on read). Whitespace is
   * trimmed. Empty entries are dropped.
   *
   * Type is `readonly string[]` for symmetry with the engine-side surfaces
   * (`composeConsumerDomains`, `OrgBoundary.*`, `BindingOptions`,
   * `GenericOidcProvider`) that all accept `readonly string[]`.
   */
  orgBoundary?: {
    extraConsumerDomains?: readonly string[];
  };

  /**
   * Keystore configuration.
   *
   * `path` is the optional override file path for the JsonFileBackend keystore
   * (used by `createKeystore({ customPath: config.keystore?.path })` at the
   * consumer boundary). The library does not read `process.env` for this signal.
   *
   * Recommended consumer-boundary bridge — config wins, env is the fallback:
   *
   *   `createKeystore({ customPath: config.keystore?.path ?? process.env.AGENTS_KEYSTORE_PATH })`
   *
   * Config-first precedence is the canonical shape because the config blob is
   * the single source of truth for the deployment; env vars are a convenience
   * for operators who haven't migrated their config files yet. If you prefer
   * env-first (e.g. ops tooling that always overrides config), invert the
   * order — but be consistent across the codebase.
   */
  keystore?: {
    path?: string;
  };

  /**
   * Dev-mode opt-in. When `true`, allows a config without `abaxxOne` or `oidc`
   * to load (this is the only gate the field affects inside the library;
   * see the `loadConfig` validator at `src/config.ts`).
   *
   * NOT a security gate. `NODE_ENV !== 'production'` is the runtime guard that
   * prevents mock auth from actually booting in prod (see `src/auth/agent.ts`,
   * `src/index.ts`, `src/auth/discovery-utils.ts`). `devMode` says "I want
   * dev-shaped config"; `NODE_ENV` says "I am, in fact, in a non-prod runtime."
   * Keep both — defense in depth.
   *
   * Independent of `createKeystore({ devMode })`. The keystore factory accepts
   * the same flag as a separate option to skip the macOS Keychain prompt;
   * passing `config.devMode` through to it is a consumer choice, not a library
   * auto-wire (`src/identity/keystore.ts` is consumer-instantiated).
   *
   * Consumers source from env at their own boundary if they want env-driven
   * config: `devMode: process.env.AGENTS_DEV_MODE === 'true'`. The library
   * itself does not read `AGENTS_DEV_MODE`.
   */
  devMode?: boolean;
}

// ─── Internal: platform identity SDK shape ───────────────────────

export type { IdSdkInstance, IdSdkVcApi, IdSdkDidApi } from './id-sdk-types.js';

export interface AuthOptions {
  redirectUri?: string;
  /** For demo/test: skip OAuth, use mock auth with this human DID */
  mockHumanDid?: string;
  /**
   * Pre-obtained OIDC identity from a completed OAuth callback.
   *
   * Web apps handle the OAuth redirect flow themselves (authorization URL →
   * browser redirect → callback → code exchange) and pass the resulting
   * identity here to create an AuthenticatedSession.
   *
   * This decouples the SDK from the HTTP transport — the SDK doesn't need
   * to know about Express routes, redirect URIs, or session cookies. The
   * web app owns the OAuth plumbing, the SDK owns identity → credential.
   *
   * The identity must include humanDid, issuer, and sub at minimum.
   * For GenericOidcProvider identities, humanDid is deterministically
   * derived from sha256(issuerUrl + '\x00' + sub).
   */
  oidcIdentity?: {
    humanDid: string;
    issuer: string;
    sub: string;
    email?: string;
    name?: string;
    org?: string;
  };
  /**
   * Authorization ceiling for this session. When supplied, the SDK enforces
   * it inside `issueCredential()`: requests that exceed the ceiling throw
   * `ScopeExceedsCeilingError` (REST server translates to 403
   * `SCOPE_EXCEEDS_CEILING`).
   *
   * Typically the caller (REST server) resolves this via
   * `resolveScopeCeiling(oidcIdentity, roleConfig)` where `roleConfig` is
   * loaded from `demo/keycloak/roles.yaml` or an equivalent enterprise
   * config. See src/auth/ceiling.ts.
   *
   * If omitted, the session gets an unrestricted ceiling — appropriate for
   * `mockHumanDid` sessions in unit tests, but the REST server's demo
   * configuration should always supply a ceiling for real OIDC sessions.
   */
  scopeCeiling?: import('./auth/ceiling.js').ScopeCeiling;
}

export interface AuthenticatedSession {
  humanDid: string;
  email?: string;
  /**
   * Authorization ceiling for this session. Computed once at authenticate()
   * time from the OIDC identity's `groups` claim against the server's
   * RoleScopeConfig. Immutable for the session's lifetime.
   *
   * Every `issueCredential()` call checks the request against this ceiling
   * and throws `ScopeExceedsCeilingError` if the request exceeds it. There
   * is no in-process override — the single source of truth for what this
   * session may grant is what they authenticated with.
   *
   * See `src/auth/ceiling.ts`.
   */
  scopeCeiling: import('./auth/ceiling.js').ScopeCeiling;
  /**
   * DID of the parent instance that issued this session's credential.
   * Present only for sessions running under an AbaxxOne tenant.
   * Derived from the verified credential's `iss` field — never from config
   * or caller input. Used by the audit logger to derive orgId and by
   * AgentVerifier to set the parent scope ceiling.
   */
  parentIssuerDid?: string;
  /**
   * Unix timestamp (seconds) when the parent-issued credential expires.
   * Checked at credential issuance time — if the parent credential has
   * expired, issueCredential() throws rather than silently issuing with
   * a stale parent. Prevents agents from operating beyond the org's
   * authorized window.
   */
  parentCredentialExp?: number;
  issueCredential(options: IssueCredentialOptions): Promise<string>;
  /**
   * Revoke a credential by JTI.
   *
   * The local `RevocationStore` write is canonical and authoritative. The
   * outbound SDK call (`sdk.vc.revokeCredential`) is best-effort notification
   * — SDK failure does NOT fail this call.
   *
   * Throws if the local `RevocationStore` write fails. Callers MUST treat
   * rejection as a hard failure (the revocation is not durable if this throws).
   *
   * Returns `{ sdkNotificationFailed?: Error }` — non-undefined if the SDK
   * notification failed. Local revocation succeeded regardless; callers may
   * log or surface this for observability. Existing callers that ignore the
   * return value continue to work unchanged.
   */
  revokeCredential(credentialId: string): Promise<{ sdkNotificationFailed?: Error }>;
}

export interface CreateAgentOptions {
  name: string;
  ownerDid?: string; // defaults to authenticated human's DID
}

/**
 * Opaque signing handle — wraps a private key without exposing it.
 * The raw key material never leaves the closure that created it.
 */
export interface AgentSigner {
  /** Sign a JWT payload, returning a compact JWS string (EdDSA / Ed25519). */
  signJwt(payload: Record<string, unknown>): string;
}

export interface RegisteredAgent {
  did: string;
  name: string;
  ownerDid: string;
  signer: AgentSigner; // Opaque — private key never exposed
  publicKey: Uint8Array;
}

// ─── Credentials ─────────────────────────────────────────────────

export interface IssueCredentialOptions {
  agent: string; // Agent DID
  columns: string[]; // e.g., ['patients.name', 'patients.dob']
  actions: 'read'[]; // v1: read-only
  expiresIn: string | number; // Duration string ('4h', '1d') or integer seconds (3600)
  metadata?: Record<string, unknown>;
  /**
   * When true, the credential MUST be issued by the parent instance.
   * If the parent provider is unavailable or fails, issueCredential() throws
   * instead of falling back to SDK or local signing.
   *
   * Enterprise deployments may require that ALL agent credentials carry the
   * org's DID as issuer for compliance and audit-trail purposes. A self-issued
   * fallback would break that invariant.
   */
  requireParent?: boolean;
}

export interface CredentialScope {
  database?: string;
  columns: string[];
  actions: string[];
}

/**
 * Options for agent-to-agent delegation.
 *
 * A supervisor agent can delegate a SUBSET of its own scope to a worker agent.
 * The delegation credential is signed by the supervisor (not the human),
 * creating a verifiable chain: human → supervisor → worker.
 *
 * Security constraints:
 * - The delegate's columns must be a subset of the delegator's columns
 * - The delegate's actions must be a subset of the delegator's actions
 * - The delegate's TTL cannot exceed the delegator's remaining TTL
 * - The ScopeEngine verifies the full chain before executing a query
 */
export interface DelegateCredentialOptions {
  /** The agent DID receiving the delegated credential */
  targetAgent: string;
  /** Column scopes to delegate — must be a subset of the source credential's scope */
  columns: string[];
  /** Actions to delegate — must be a subset of the source credential's actions */
  actions: 'read'[];
  /** How long the delegation lasts — cannot exceed the source credential's remaining TTL */
  expiresIn: string | number;
  /** Optional metadata for auditing (e.g., reason for delegation) */
  metadata?: Record<string, unknown>;
}

// ─── Audit ───────────────────────────────────────────────────────

export interface AuditRecord {
  id: string; // UUID
  timestamp: string; // ISO 8601
  agentDid: string;
  ownerDid: string;
  credentialId: string; // Hash of the VC JWT
  queryHash: string; // SHA-256 of the SQL query
  columnsAccessed: string[];
  rowCount: number;
  durationMs: number;
  previousHash: string; // SHA-256 of previous record (hash chain)
  signature: string; // JWS signed by agent's DID private key
  /** Hash schema version. New records are always V3; V1/V2 exist only in pre-launch stores. */
  version: 1 | 2 | 3;
  /** 'success' for queries that executed, 'rejected' for scope violations / replays / etc. */
  status?: 'success' | 'rejected';
  /** Human-readable rejection reason (e.g., "Scope violation: queried unauthorized columns") */
  reason?: string;
  /** Machine-readable code matching the error that triggered rejection */
  reasonCode?: string;
  /**
   * V3 field: parent-instance organization ID.
   *
   * When agents operate under a parent instance (e.g. AbaxxOne tenant), audit
   * records must trace back to the organization that authorized the agent.
   * Enables per-organization audit queries, compliance reporting, and
   * multi-tenant isolation in enterprise deployments.
   *
   * NEVER accepted from caller-supplied parameters. The scope engine derives
   * this from the verified credential's `iss` field and populates the
   * `AuditEntry` before passing it to the AuditLogger. This prevents audit
   * spoofing where a caller claims to act on behalf of an organization they
   * don't belong to.
   *
   * Nullable: free-tier agents (did:key, generic OIDC) have no orgId. Only
   * tenant-issued credentials carry an organizational context.
   */
  orgId?: string;
}

export interface AuditEntry {
  agentDid: string;
  ownerDid: string;
  credentialJwt: string;
  sql: string;
  columnsAccessed: string[];
  rowCount: number;
  durationMs: number;
  /**
   * Parent-instance organization ID.
   *
   * Populated by the scope engine from the verified credential's issuer field.
   * The AuditLogger does not validate or derive this value — it trusts the
   * scope engine to have extracted it from a cryptographically verified source.
   *
   * When present, the resulting AuditRecord is V3 (orgId enters the hash chain).
   * When absent, version stays at V2.
   *
   * See `AuditRecord.orgId` for the full security rationale.
   */
  orgId?: string;
}

// ─── Verification ────────────────────────────────────────────────

/**
 * Options for VcVerifier.verify().
 *
 * Security note: these are NOT escape hatches — they are precise controls for
 * callers that have legitimate reasons to skip a specific check.
 *
 * skipScopeCheck: set true for IdentityBindingCredentials, which carry no
 *   scope.columns by design. Without this flag, verify() returns MALFORMED on
 *   any binding VC. This is an architectural property, not a bypass.
 *
 * expectedSubject: when set, verify() asserts payload.sub === expectedSubject
 *   after signature validation. Prevents confused-deputy attacks where an agent
 *   presents a valid VC issued for a different agent DID. Callers that know the
 *   expected requesting-agent DID SHOULD always pass this.
 */
export interface VerifyOptions {
  /**
   * Skip the scope.columns structure check. Use for IdentityBindingCredential
   * and other VC types that legitimately carry no scope payload.
   */
  skipScopeCheck?: boolean;

  /**
   * Assert that payload.sub equals this DID after signature validation.
   * Prevents a valid credential issued for agent-A from being presented by agent-B.
   * Pass the DID of the agent making the request.
   */
  expectedSubject?: string;

  /**
   * Assert that payload.aud matches this DID.
   * Prevents VP replay across servers. When Agent A presents a credential
   * to Server X, the VP's audience should be Server X's verifierDid. Without
   * this check, a VP captured from Server X can be replayed to Server Y.
   * Pass the verifierDid of the server validating the credential.
   */
  expectedAudience?: string;
}

export interface VerificationResult {
  valid: boolean;
  /**
   * WRONG_SUBJECT: credential signature is cryptographically valid but was
   * issued for a different agent DID than the one presenting it. Distinct from
   * INVALID_SIGNATURE — the key is correct, the binding is wrong. Conflating
   * these status codes sends developers debugging the wrong thing (key
   * rotation vs authorization).
   */
  status:
    | 'VALID'
    | 'INVALID_SIGNATURE'
    | 'EXPIRED'
    | 'REVOKED'
    | 'SUSPENDED'
    | 'UNKNOWN_ISSUER'
    | 'MALFORMED'
    | 'REPLAYED'
    | 'WRONG_SUBJECT'
    | 'WRONG_AUDIENCE'
    | 'MIGRATION_DETECTED';
  credential?: DecodedCredential;
  error?: string;
}

export interface DecodedCredential {
  issuer: string;
  subject: string;
  issuedAt: Date;
  expiresAt: Date;
  /** Optional: IdentityBindingCredentials carry no scope by design. */
  scope?: CredentialScope;
  credentialStatus?: {
    id: string;
    type: string;
    statusPurpose: string;
    statusListIndex: string;
    statusListCredential: string;
  };
  /**
   * VC type array from the credential payload (e.g., ['VerifiableCredential',
   * 'DelegatedAgentScopeCredential']). Used by the ScopeEngine to detect
   * delegated credentials and apply delegation-chain verification instead
   * of the direct issuer == ownerDid check.
   */
  vcTypes?: string[];
  /**
   * Delegation chain — array of source credential JWTs. DWN-aligned: stored
   * as a top-level JWT claim (not inside credentialSubject), matching
   * abaxx-id-go/json-schemas/permissions-grant.json where delegationChain
   * sits alongside authorization and descriptor. The owner check walks the
   * chain: source VC issuer == human owner, source VC subject == delegated
   * VC issuer. One level only unless `delegated: true`.
   */
  delegationChain?: string[];
  /**
   * Migration credential claims, present only when vcTypes includes
   * IdentityMigrationCredential. Extracted by VcVerifier for the migration
   * detection pre-step in the scope engine.
   */
  migrationClaims?: MigrationCredentialClaims;
}

// ─── Identity Migration ─────────────────────────────────────────

/**
 * VC type for identity migration credentials. When a user migrates from
 * did:key to did:dht, the tenant admin issues a VC of this type to bridge the
 * old DID to the new DID.
 *
 * Must be treated like IdentityBindingCredential for scope checks
 * (`skipScopeCheck: true`) — migration credentials carry no `scope.columns`
 * by design.
 */
export const IDENTITY_MIGRATION_CREDENTIAL = 'IdentityMigrationCredential';

/**
 * Claims embedded in an IdentityMigrationCredential.
 *
 * `oidcSubject` is required to prevent a compromised tenant admin from
 * mapping Alice's old DID to the attacker's new DID. The consuming instance
 * cross-verifies `oidcSubject` against the existing IdentityBindingCredential
 * on file for the `previousDid`.
 */
export interface MigrationCredentialClaims {
  /** The old DID being migrated away from (must be did:key for free-tier upgrades). */
  previousDid: string;
  /** The OIDC subject identifier that links both DIDs to the same human. */
  oidcSubject: string;
  /** How the identity link was verified (e.g., "oidc-verified"). */
  migrationMethod: string;
  /** The OIDC issuer URL for the identity provider (e.g., Microsoft Entra tenant). */
  oidcIssuer: string;
  /** When the migration was initiated. */
  migratedAt: string;
}

/**
 * Audit record type for migration events. Extends the base AuditRecord
 * with migration-specific fields. The migration audit record bridges the
 * hash chain across the DID transition: its previousHash links to the last
 * record under the old DID, and subsequent records use the new DID.
 */
export interface MigrationAuditFields {
  /** The DID being migrated from. */
  oldDid: string;
  /** The DID being migrated to. */
  newDid: string;
  /** SHA-256 hash of the migration credential JWT. */
  migrationCredentialHash: string;
  /** OIDC issuer that verified the identity link. */
  oidcIssuer: string;
  /** Number of agents whose owner_did was updated. */
  agentsMigrated: number;
  /** Number of context entries whose owner_did was updated. */
  contextEntriesMigrated: number;
  /** Grace period expiry timestamp (ISO 8601). */
  gracePeriodExpiresAt: string;
}

// ─── Column Encryption ──────────────────────────────────────────

export interface ColumnKeyRecord {
  id: string;
  tableName: string;
  columnName: string;
  encryptedKey: Buffer;
  algorithm: string;
  createdAt: Date;
  rotatedAt?: Date;
}

export interface EncryptedColumnMeta {
  tableName: string;
  columnName: string;
  keyId: string;
  originalType: string;
  isEncrypted: boolean;
}

// ─── Internal Types ──────────────────────────────────────────────

export interface ColumnKeyMap {
  /** Maps "table.column" → decrypted AES key */
  get(tableColumn: string): Buffer | undefined;
  has(tableColumn: string): boolean;
  keys(): IterableIterator<string>;
}
