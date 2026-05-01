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
 * SessionEnvelope — re-establishment metadata persisted per session token.
 *
 * Process-local `Map<token, SessionEntry>` disappears on restart and is
 * invisible to peer instances behind a load balancer. This envelope is the
 * minimum metadata needed to re-call `createSessionFromDid` on a cross-
 * instance hit, reconstructing a live `AuthenticatedSession` that was never
 * itself serialized.
 *
 * The envelope is NOT a serialized session. `AuthenticatedSession` holds
 * `humanPrivateKey`, `verifier`, `sdk`, `parentProvider` references —
 * closures over instance-local state. Persisting them would require
 * serializing JavaScript closures (impossible) and private keys (a security
 * regression). Instead we persist only:
 *
 *   - Identity fields (DID, email, OIDC claims)
 *   - A compact parent JWT whose authority is re-verified on every read
 *   - Lifecycle metadata (createdAt, expiresAt)
 *   - Provider binding (issuer URL — keyed into a local allowlist)
 *
 * Authority fields (scope ceiling, parent-issuer DID, parent-credential exp)
 * are re-derived / re-verified from these bytes on every re-establishment.
 * Envelope bytes are never trusted as authority — they are trust roots for
 * the server to re-compute authority against.
 *
 * Security: identity fields (humanDid, oidcSubject, oidcIssuer) are
 * key-equivalent material. `createOidcSession` derives its Ed25519 keypair
 * from sha256(oidcIssuer || '\x00' || oidcSubject). A row-tamper that
 * rewrites oidcSubject synthesizes a different key on re-establishment ->
 * impersonation vector. MAC (HMAC-SHA256 over canonical envelope encoding,
 * HKDF-derived key from master key) is the only defense against this specific
 * tamper class. MAC is not confidentiality — envelope fields remain readable
 * in the DB.
 *
 * Envelope size cap: canonical-encoded byte length MUST be <= 32768 (32KB).
 * Defense against unbounded `oidcGroupClaims` from self-hosted Keycloak
 * tenants — the one envelope field outside Abaxx's issuance control.
 *
 * Not serializable by design:
 *   - humanPrivateKey — closures stay instance-local. Non-portable sessions
 *     are rejected at put() with SessionNotPortableError.
 *   - parentAccessToken / refresh tokens — no OAuth-secret persistence.
 *     Cross-instance hits requiring a live parent token fall back to
 *     re-auth-on-miss.
 *   - derived column keys — never on sessions (ScopeEngine concern).
 */
export interface SessionEnvelope {
  /** The human DID this session represents (did:dht or did:key). */
  humanDid: string;
  /** Optional email claim. */
  email?: string;

  /** OIDC issuer URL (iss claim). Keyed into the local allowlist. */
  oidcIssuer: string;
  /** OIDC subject (sub claim). */
  oidcSubject: string;
  /** OIDC group claims (if any) — used to re-derive scope ceiling. */
  oidcGroupClaims?: string[];
  /** Optional tenant URL for keycloak/abaxx-one providers. */
  oidcTenantUrl?: string;

  parentJwt?: string;
  providerKind: 'oidc-google' | 'oidc-microsoft' | 'oidc-abaxx-one' | 'oidc-keycloak';

  /** Unix ms when this envelope was first created. */
  createdAt: number;
  /**
   * Unix ms authoritative expiry. Set by the storage layer
   * (`expires_at = NOW() + ttlSeconds`), echoed back in the returned envelope
   * so consumers can use it for cache-TTL computation.
   */
  expiresAt: number;
}

/** Options for SessionStore.put(). `ttlSeconds` is authoritative; the store computes `expiresAt` storage-side. */
export interface SessionPutOptions {
  ttlSeconds: number;
}

/**
 * SessionStore — durable re-establishment envelope persistence.
 *
 * Makes server session state durable across process restart and coherent
 * across instances behind a load balancer.
 *
 * Error contract: all methods throw on backing-store failure at runtime.
 * NEVER swallow. HTTP handler maps throws to 503. No silent in-memory fallback.
 */
export interface SessionStore {
  /**
   * Hot path: read an envelope by token.
   *
   * Returns null if:
   *   - Token is unknown
   *   - Row's expires_at < NOW() (expired — caller re-authenticates)
   *
   * Throws on:
   *   - MAC mismatch (EnvelopeIntegrityError) — row-tamper detected
   *   - Backing-store failure (SQL error, connection loss, etc.)
   */
  get(token: string): Promise<SessionEnvelope | null>;

  /**
   * Persist an envelope with a TTL (seconds).
   *
   * `expires_at` is computed storage-side as `NOW() + ttlSeconds`.
   *
   * Throws on:
   *   - `envelope.providerKind === 'mock'` (ProviderNotAllowedError). Mock
   *     sessions are instance-local by design and must never be persisted.
   *   - Canonical-encoded envelope byte length > MAX_ENVELOPE_BYTES
   *     (EnvelopeTooLargeError).
   *   - Backing-store failure.
   */
  put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void>;

  /**
   * Revoke a session. Used by admin-revoke path and on token rotation.
   * Idempotent — delete() on an unknown token is a no-op.
   */
  delete(token: string): Promise<void>;

  /**
   * GDPR Art. 17 helper. Deletes all sessions for a given humanDid.
   * Returns count deleted.
   */
  deleteByHumanDid(humanDid: string): Promise<number>;

  /**
   * Consumer-scheduled pruning. Deletes rows WHERE expires_at < beforeTs
   * (default NOW()). Optional `limit` bounds single-call DELETE size to avoid
   * million-row locks.
   *
   * Returns count deleted.
   */
  pruneExpired(beforeTs?: Date, limit?: number): Promise<number>;
}

/**
 * Thrown when envelope MAC verification fails at get() time.
 *
 * This is a tamper indicator. Callers should NOT retry with the same token.
 * HTTP handler maps to 401 `SESSION_INTEGRITY_FAILED`.
 */
export class EnvelopeIntegrityError extends Error {
  readonly code = 'SESSION_INTEGRITY_FAILED' as const;
  constructor(message = 'Session envelope integrity check failed') {
    super(message);
    this.name = 'EnvelopeIntegrityError';
  }
}

/**
 * Thrown by server-side rehydrate when a session is not portable — typically
 * because it was created via createMockSession or carries a closure-bound
 * humanPrivateKey. These sessions stay instance-local.
 */
export class SessionNotPortableError extends Error {
  readonly code = 'SESSION_NOT_PORTABLE' as const;
  constructor(message = 'Session is instance-local and cannot be externalized') {
    super(message);
    this.name = 'SessionNotPortableError';
  }
}

/**
 * Thrown when put() encounters providerKind='mock' OR when re-establishment
 * encounters an envelope whose oidcIssuer is not in OIDC_ALLOWED_ISSUERS.
 */
export class ProviderNotAllowedError extends Error {
  readonly code = 'PROVIDER_NOT_ALLOWED' as const;
  readonly issuer?: string;
  constructor(issuer?: string, message?: string) {
    super(message ?? `Provider not allowed${issuer ? `: ${issuer}` : ''}`);
    this.name = 'ProviderNotAllowedError';
    this.issuer = issuer;
  }
}

/**
 * Thrown when put() encounters a canonical-encoded envelope exceeding
 * MAX_ENVELOPE_BYTES (32768 / 32KB).
 */
export class EnvelopeTooLargeError extends Error {
  readonly code = 'ENVELOPE_TOO_LARGE' as const;
  readonly sizeBytes: number;
  readonly maxBytes: number;
  constructor(sizeBytes: number, maxBytes: number) {
    super(`Session envelope exceeds size cap: ${sizeBytes} > ${maxBytes} bytes`);
    this.name = 'EnvelopeTooLargeError';
    this.sizeBytes = sizeBytes;
    this.maxBytes = maxBytes;
  }
}
