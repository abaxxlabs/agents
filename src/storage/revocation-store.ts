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
 * Durable JTI revocation with bounded cross-instance staleness. The local store
 * is authoritative; callers must treat persistence failure as a hard failure.
 */
export interface RevocationStore {
  /** Returns whether a JTI is revoked, subject to the configured cache bound. */
  isRevoked(jti: string): Promise<boolean>;

  /**
   * Idempotently persists a revocation.
   * @param jti - The credential ID (JWT ID claim) to revoke.
   * @param opts.reason - Optional human-readable reason for revocation.
   * @param opts.credentialExp - Credential expiry used to determine safe pruning.
   */
  revoke(jti: string, opts: { reason?: string; credentialExp?: Date }): Promise<void>;

  /** Loads current revocations for startup cache warm-up. */
  loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>>;

  /**
   * Deletes revocations for credentials expired before the cutoff.
   * @param beforeTs - Defaults to 30 days before the current time.
   * @returns The number of deleted revocations.
   */
  pruneExpired(beforeTs?: Date): Promise<number>;
}
