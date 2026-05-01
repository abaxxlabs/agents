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

/** Structured error types — machine-readable code + diagnostic message on every error. */

export class AgentScopeError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AgentScopeError';
  }
}

// ─── Credential Errors ───────────────────────────────────────────

export class CredentialInvalidError extends AgentScopeError {
  constructor(agentDid: string, reason?: string) {
    super(
      'CREDENTIAL_INVALID',
      `Signature verification failed for agent ${agentDid}${reason ? ` — ${reason}` : ''}`,
      { agentDid },
    );
    this.name = 'CredentialInvalidError';
  }
}

export class CredentialExpiredError extends AgentScopeError {
  constructor(agentDid: string, expiredAt: Date) {
    super(
      'CREDENTIAL_EXPIRED',
      `Credential for agent ${agentDid} expired at ${expiredAt.toISOString()} (current: ${new Date().toISOString()})`,
      { agentDid, expiredAt: expiredAt.toISOString() },
    );
    this.name = 'CredentialExpiredError';
  }
}

export class CredentialRevokedError extends AgentScopeError {
  constructor(credentialId: string, issuerDid: string, suspended = false) {
    super(
      'CREDENTIAL_REVOKED',
      `Credential ${credentialId} has been ${suspended ? 'suspended' : 'revoked'} by issuer ${issuerDid}`,
      { credentialId, issuerDid, suspended },
    );
    this.name = 'CredentialRevokedError';
  }
}

export class CredentialMalformedError extends AgentScopeError {
  constructor(reason: string) {
    super(
      'CREDENTIAL_MALFORMED',
      `Credential JWT missing required claim — ${reason}. Expected schema: https://abaxx.tech/schemas/agents-v1`,
      {},
    );
    this.name = 'CredentialMalformedError';
  }
}

export class UnknownIssuerError extends AgentScopeError {
  constructor(issuerDid: string, reason?: string) {
    super(
      'UNKNOWN_ISSUER',
      `Could not resolve issuer ${issuerDid}${reason ? ` — ${reason}` : ''}`,
      { issuerDid },
    );
    this.name = 'UnknownIssuerError';
  }
}

// ─── DID Resolution Errors ───────────────────────────────────────

export class DidResolutionFailedError extends AgentScopeError {
  constructor(did: string, reason: string) {
    super('DID_RESOLUTION_FAILED', `Could not resolve ${did} — ${reason}`, { did });
    this.name = 'DidResolutionFailedError';
  }
}

// ─── Auth Errors ─────────────────────────────────────────────────

export class AuthUnavailableError extends AgentScopeError {
  constructor(tenantUrl: string) {
    super(
      'AUTH_UNAVAILABLE',
      `Cannot reach Abaxx One at ${tenantUrl} — human authentication unavailable. Existing credentials remain valid until expiry.`,
      { tenantUrl },
    );
    this.name = 'AuthUnavailableError';
  }
}

export class DiscoveryEndpointBlockedError extends AgentScopeError {
  constructor(
    field: string,
    endpointHost: string,
    issuerOrigin: string,
    public readonly configMissing: boolean,
    providerLabel?: string,
  ) {
    const reason = configMissing
      ? 'no allowedCrossOriginHosts configured for this issuer'
      : `host is not in the issuer's allowedCrossOriginHosts`;
    const prefix = providerLabel ? `${providerLabel} discovery` : 'OIDC discovery';
    super(
      'DISCOVERY_ENDPOINT_BLOCKED',
      `${prefix} ${field} blocked: endpoint host "${endpointHost}" differs from issuer origin ${issuerOrigin} — ${reason}`,
      { field, endpointHost, issuerOrigin, configMissing },
    );
    this.name = 'DiscoveryEndpointBlockedError';
  }
}

// ─── Database Errors ─────────────────────────────────────────────

export class DbConnectionFailedError extends AgentScopeError {
  constructor(host: string, reason?: string) {
    super(
      'DB_CONNECTION_FAILED',
      `Cannot connect to PostgreSQL at ${host}${reason ? ` — ${reason}` : ''}`,
      { host },
    );
    this.name = 'DbConnectionFailedError';
  }
}

// ─── Audit Errors ────────────────────────────────────────────────

export class AuditWriteFailedError extends AgentScopeError {
  constructor(reason: string) {
    super(
      'AUDIT_WRITE_FAILED',
      `Could not write audit record — ${reason}. Query blocked.`,
      { reason },
    );
    this.name = 'AuditWriteFailedError';
  }
}

// ─── Query Errors ───────────────────────────────────────────────

/**
 * SQL parse failure, mutation detected, or non-SELECT statement.
 * Distinct from CredentialInvalidError — the credential may be perfectly valid,
 * but the query itself is rejected.
 */
export class QueryRejectedError extends AgentScopeError {
  constructor(agentDid: string, reason: string) {
    super('QUERY_REJECTED', `Query rejected for agent ${agentDid} — ${reason}`, { agentDid });
    this.name = 'QueryRejectedError';
  }
}

/**
 * Query references columns outside the credential's authorized scope.
 * HTTP responses must NOT include column names (schema-oracle prevention).
 * Internal audit records DO include the full detail.
 */
export class ScopeViolationError extends AgentScopeError {
  constructor(
    agentDid: string,
    /** Columns requested that are out of scope — included in audit, stripped from HTTP responses */
    public readonly requestedColumns: string[],
    /** Columns the credential authorizes */
    public readonly authorizedColumns: string[],
  ) {
    super('SCOPE_VIOLATION', `Agent ${agentDid} queried columns outside credential scope`, {
      agentDid,
    });
    this.name = 'ScopeViolationError';
  }

  /**
   * Coarsened JSON for HTTP responses — omits column names to prevent
   * schema enumeration attacks.
   */
  toSafeResponse(): { code: string; message: string } {
    return {
      code: this.code,
      message:
        'Query references columns outside the authorized scope. Request a credential with broader scope.',
    };
  }
}

/**
 * Credential JTI has already been consumed (replay protection).
 * Distinct from CredentialInvalidError — the credential was valid when first
 * presented but cannot be reused. Includes JTI and recovery instruction so the
 * caller knows exactly what happened and how to fix it.
 */
export class CredentialReplayedError extends AgentScopeError {
  constructor(
    agentDid: string,
    public readonly jti: string,
  ) {
    super(
      'CREDENTIAL_REPLAYED',
      `Credential ${jti} for agent ${agentDid} has already been used. Issue a new credential with issueCredential().`,
      { agentDid, jti },
    );
    this.name = 'CredentialReplayedError';
  }
}

// ─── Scope Warnings ──────────────────────────────────────────────

export class ScopeWarning extends AgentScopeError {
  constructor(column: string) {
    super(
      'SCOPE_WARNING',
      `Column '${column}' is in credential scope but is not encrypted — returning cleartext. Encrypt with: npx agents encrypt ${column}`,
      { column },
    );
    this.name = 'ScopeWarning';
  }
}

// ─── Key Rotation Errors ─────────────────────────────────────────

/**
 * Phase tag for KeyRotationFailedError.
 *
 * Phases in order for rotateColumnKey:
 *   'unwrap-old-key' — failed to decrypt the wrapped column key from agent_keys.
 *     Usual cause: wrong masterKey passed, or agent_keys row is corrupted.
 *   'decrypt-row' — GCM auth tag failure on a data row during re-encryption pass.
 *     Usual cause: row was already corrupted / written under a different key.
 *   'encrypt-row' — AES-GCM cipher error while re-encrypting. Extremely rare
 *     (crypto primitive failure).
 *   'wrap-new-key' — failed to wrap the new column key under the master key.
 *   'update-agent-keys' — failed to UPDATE agent_keys with the new wrapped key.
 *   'audit-append' — failed to write the audit record inside the transaction.
 *     The INSERT is the last statement before COMMIT; failure here still rolls
 *     back the whole transaction (column stays on the old key). The phase tag
 *     lets operators distinguish audit-subsystem failures from earlier phases.
 *
 * For rewrapColumnKey, only: 'unwrap-old-key', 'wrap-new-key',
 * 'update-agent-keys', 'audit-append' — no row-level phases.
 */
export type KeyRotationPhase =
  | 'unwrap-old-key'
  | 'decrypt-row'
  | 'encrypt-row'
  | 'wrap-new-key'
  | 'update-agent-keys'
  | 'audit-append';

/**
 * Thrown by rotateColumnKey() and rewrapColumnKey() on any failure.
 *
 * The phase field identifies WHERE in the operation the failure occurred,
 * enabling operators to distinguish:
 *   - wrong master key ('unwrap-old-key')
 *   - pre-existing data corruption ('decrypt-row' — row was unreadable before rotation)
 *   - infra failure ('update-agent-keys', 'audit-append')
 *
 * The underlying error is preserved as `cause` for diagnostic purposes.
 *
 * On 'audit-append' failure: the audit INSERT is the last statement inside the
 * transaction, so a failure here still rolls back the whole transaction —
 * the column remains on its old key. A post-rotation commit that is unlogged
 * is NOT possible with the current ordering; see rotateColumnKey JSDoc for the
 * rollback invariant.
 */
export class KeyRotationFailedError extends Error {
  constructor(
    public readonly phase: KeyRotationPhase,
    public override readonly cause: unknown,
  ) {
    super(`Key rotation failed at phase '${phase}': ${(cause as Error)?.message ?? String(cause)}`);
    this.name = 'KeyRotationFailedError';
  }
}

// ─── Encryption Errors ───────────────────────────────────────────

export class DecryptionFailedError extends AgentScopeError {
  constructor(column: string, reason?: string) {
    super(
      'DECRYPTION_FAILED',
      `Failed to decrypt column '${column}'${reason ? ` — ${reason}` : ''}`,
      { column },
    );
    this.name = 'DecryptionFailedError';
  }
}

export class MasterKeyMissingError extends AgentScopeError {
  constructor() {
    super(
      'MASTER_KEY_MISSING',
      // The message intentionally points at `parseMasterKeyHex` (not raw
      // `Buffer.from(..., 'hex')`) because `Buffer.from` silently drops
      // non-hex characters and produces an undersized buffer — exactly the
      // footgun this release closes. The error message must not teach the
      // unsafe pattern.
      "Master key not provided. Pass a 32-byte Buffer as injections.masterKey to AgentScope.create(config, injections). For env-var bootstrap, import parseMasterKeyHex from '@abaxxlabs/agents/bootstrap' (strict 64-hex validation). See docs/migration-byok.md for full examples.",
      {},
    );
    this.name = 'MasterKeyMissingError';
  }
}

/**
 * Thrown when persisted column keys exist but cannot be decrypted with the supplied master key.
 *
 * Mass-fail (not any-fail): legitimate rotation states can briefly mix old + new wrapped keys.
 * Throws rather than warn-and-skip because a wrong-key boot would silently succeed with an empty
 * key map — downstream queries return `[ENCRYPTED]` bytes with no audible signal.
 */
export class MasterKeyMismatchError extends AgentScopeError {
  constructor(failedCount: number, totalCount?: number) {
    super(
      'MASTER_KEY_MISMATCH',
      'Column keys exist but cannot be decrypted with the provided master key. Wrong key or corrupted data.',
      { failedCount, ...(totalCount !== undefined ? { totalCount } : {}) },
    );
    this.name = 'MasterKeyMismatchError';
  }
}

// ─── Tier Errors ────────────────────────────────────────────────

/**
 * Thrown when requesting a parent-issued agent credential from AbaxxOne fails.
 * Includes tenant URL, HTTP status, and a recovery hint so the error is actionable.
 */
export class ParentCredentialRequestFailedError extends AgentScopeError {
  constructor(
    public readonly tenantUrl: string,
    public readonly httpStatus: number | undefined,
    recoveryHint?: string,
  ) {
    super(
      'PARENT_CREDENTIAL_REQUEST_FAILED',
      `Failed to obtain agent credential from parent instance at ${tenantUrl}` +
        (httpStatus ? ` (HTTP ${httpStatus})` : '') +
        `. ${recoveryHint ?? 'Check that the tenant URL is correct and the access token is valid.'}`,
      { tenantUrl, httpStatus },
    );
    this.name = 'ParentCredentialRequestFailedError';
  }
}

// ─── Numeric Precision Errors ───────────────────────────────────

export class PrecisionLossError extends AgentScopeError {
  constructor(rawValue: string) {
    super(
      'PRECISION_LOSS',
      `PostgreSQL bigint value '${rawValue}' exceeds Number.MAX_SAFE_INTEGER and cannot be safely represented as a JavaScript number`,
      { rawValue },
    );
    this.name = 'PrecisionLossError';
  }
}

export class CapabilityRequiresPaidTierError extends AgentScopeError {
  constructor(
    public readonly capability: string,
    public readonly namespace: string,
  ) {
    super(
      'CAPABILITY_REQUIRES_PAID_TIER',
      `Capability "${capability}" in namespace "${namespace}" requires AbaxxOne. Sign up at https://abaxx.tech/one`,
      { capability, namespace, signupUrl: 'https://abaxx.tech/one' },
    );
    this.name = 'CapabilityRequiresPaidTierError';
  }
}
