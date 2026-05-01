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
 * RevocationStore — durable JTI revocation with bounded staleness across instances.
 *
 * Makes revocation state durable across process restart and coherent across
 * instances. Without this, revocations live in process-local Set<string> and
 * disappear on restart — a security-posture gap.
 *
 * Minimum contract to support (a) hot-path isRevoked check on every credential
 * verification, (b) rare revoke write, (c) startup cache warm-up, (d)
 * background pruning of expired revocations.
 *
 * Lives inside StorageBackend rather than as a standalone hierarchy: it is a
 * security control (same precedent as AuditStore). Storage-layer bugs that
 * affect RevocationStore MUST be treated as security incidents, not
 * operational incidents.
 *
 * Error contract: revoke() throws on failure. NEVER swallow. A silent success
 * that did not actually persist is a security-invariant violation. Callers
 * MUST treat rejection as a hard failure.
 *
 * Revocation authority: local store is canonical. SDK call
 * (sdk.vc.revokeCredential) is a best-effort outbound notification. SDK
 * failure does NOT fail the revocation; surfaced in an sdkNotificationFailed?
 * field so callers can observe if they care.
 *
 * Cross-instance coherency: 30-second configurable poll by default.
 */
export interface RevocationStore {
  /**
   * Hot path: called on every credential verification. Returns true if the
   * JTI has been revoked. Bounded by cache staleness (default 30s across
   * instances).
   */
  isRevoked(jti: string): Promise<boolean>;

  /**
   * Rare admin action. Idempotent — repeat revoke on same jti is a no-op.
   * Throws on storage failure — caller MUST treat rejection as a hard failure.
   * A swallowed failure means the credential appears revoked in the caller's
   * eyes but is NOT durably stored — a security invariant violation.
   *
   * @param jti - The credential ID (JWT ID claim) to revoke.
   * @param opts.reason - Optional human-readable reason for revocation.
   * @param opts.credentialExp - The original credential's exp claim. Used by
   *   pruneExpired() to determine when the revocation record is safe to delete.
   *   Nullable for non-expiring credentials (they are never pruned).
   */
  revoke(jti: string, opts: { reason?: string; credentialExp?: Date }): Promise<void>;

  /**
   * Startup cache warm-up. Loads all current revocations from storage into
   * an in-process cache. Non-fatal if unavailable — VcVerifier continues with
   * a cold cache (reads fall through to storage until the cache warms up).
   *
   * Returns an array of revoked JTIs with their expiry dates (for cache
   * eviction scheduling).
   */
  loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>>;

  /**
   * Background prune: deletes revocations whose underlying credential has already
   * expired (expires_at < beforeTs). Conservative window: default 30 days
   * post-expiry to ensure all cross-instance caches have evicted the entry.
   *
   * Returns the count of deleted rows.
   *
   * @param beforeTs - Delete revocations whose credentialExp is before this date.
   *   Defaults to (now - 30 days) if not supplied.
   */
  pruneExpired(beforeTs?: Date): Promise<number>;
}
