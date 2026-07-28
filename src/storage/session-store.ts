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
 * Minimal metadata required to rebuild a live session across processes.
 * Private keys, OAuth secrets, closures, and derived column keys are never
 * persisted. Authority is re-verified on every re-establishment.
 *
 * Identity fields are key-equivalent, so an HMAC protects envelope integrity;
 * it does not provide confidentiality. Canonical envelopes are capped at 32KB.
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
  /** OIDC groups used to re-derive the scope ceiling. */
  oidcGroupClaims?: string[];
  /** Optional tenant URL for Keycloak and AbaxxOne providers. */
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

/** Options for SessionStore.put(). */
export interface SessionPutOptions {
  ttlSeconds: number;
}

/**
 * Durable session re-establishment envelopes shared across server instances.
 * Backing-store failures are never replaced with a silent in-memory fallback.
 */
export interface SessionStore {
  /**
   * Reads an unexpired envelope by token.
   * @returns Null when the token is unknown or expired.
   * @throws {EnvelopeIntegrityError} When MAC verification fails.
   */
  get(token: string): Promise<SessionEnvelope | null>;

  /**
   * Persists an envelope with a storage-authoritative TTL.
   * @throws {ProviderNotAllowedError} When the provider cannot be persisted.
   * @throws {EnvelopeTooLargeError} When canonical data exceeds the size limit.
   */
  put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void>;

  /** Idempotently deletes a session by token. */
  delete(token: string): Promise<void>;

  /** Deletes all sessions for a human DID and returns the count. */
  deleteByHumanDid(humanDid: string): Promise<number>;

  /**
   * Deletes expired sessions. The optional limit bounds each delete operation.
   */
  pruneExpired(beforeTs?: Date, limit?: number): Promise<number>;
}

/** Indicates persisted session-envelope tampering. */
export class EnvelopeIntegrityError extends Error {
  readonly code = 'SESSION_INTEGRITY_FAILED' as const;
  constructor(message = 'Session envelope integrity check failed') {
    super(message);
    this.name = 'EnvelopeIntegrityError';
  }
}

/** Indicates a session contains instance-local state and cannot be persisted. */
export class SessionNotPortableError extends Error {
  readonly code = 'SESSION_NOT_PORTABLE' as const;
  constructor(message = 'Session is instance-local and cannot be externalized') {
    super(message);
    this.name = 'SessionNotPortableError';
  }
}

/** Indicates a provider cannot be persisted or re-established. */
export class ProviderNotAllowedError extends Error {
  readonly code = 'PROVIDER_NOT_ALLOWED' as const;
  readonly issuer?: string;
  constructor(issuer?: string, message?: string) {
    super(message ?? `Provider not allowed${issuer ? `: ${issuer}` : ''}`);
    this.name = 'ProviderNotAllowedError';
    this.issuer = issuer;
  }
}

/** Indicates a canonical envelope exceeds the configured size limit. */
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
