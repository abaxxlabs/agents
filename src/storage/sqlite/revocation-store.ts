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
 * SqliteRevocationStore — SQLite implementation of RevocationStore.
 *
 * Single-process durable JTI revocation. SQLite adaptations: ISO 8601 TEXT
 * timestamps, no LISTEN/NOTIFY. Uses BEGIN IMMEDIATE on isRevoked() and
 * revoke() to close the concurrent revoke+verify race.
 *
 * Security: storage bugs here are security incidents, not operational ones.
 * A missed revocation is a credential-validity violation.
 */

import type { Database } from 'better-sqlite3';
import type { RevocationStore } from '../types.js';

export class SqliteRevocationStore implements RevocationStore {
  private readonly db: Database;

  // Simple Set (not Map with expiry): pruneExpired() is the explicit eviction path.
  // Lazy eviction on isRevoked() could mask revocation of an expired credential.
  private readonly cache = new Set<string>();

  constructor(db: Database) {
    this.db = db;
  }

  /**
   * Hot path: O(1) Set lookup, falls back to DB under BEGIN IMMEDIATE if cache miss.
   * BEGIN IMMEDIATE closes the concurrent revoke+verify race window.
   */
  async isRevoked(jti: string): Promise<boolean> {
    if (this.cache.has(jti)) return true;

    // DB lookup under RESERVED lock — prevents concurrent revoke+verify race.
    // Cast to any: .immediate() exists on better-sqlite3 Transaction but isn't typed.
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const found = (this.db as any)
      .transaction(() => {
        const row = (this.db as any)
          .prepare(`SELECT jti FROM revoked_credentials WHERE jti = ?`)
          .get(jti);
        return !!row;
      })
      .immediate();
    /* eslint-enable @typescript-eslint/no-explicit-any */

    if (found) {
      this.cache.add(jti);
    }
    return found;
  }

  /**
   * Revoke a JTI under BEGIN IMMEDIATE. Idempotent (ON CONFLICT DO NOTHING).
   * Throws on any SQLite error — callers must treat rejection as a hard failure.
   */
  async revoke(jti: string, opts: { reason?: string; credentialExp?: Date }): Promise<void> {
    if (!jti || typeof jti !== 'string') {
      throw new Error('RevocationStore.revoke: jti must be a non-empty string');
    }

    /* eslint-disable @typescript-eslint/no-explicit-any -- .immediate() not exposed in Transaction types */
    (this.db as any)
      .transaction(() => {
        (this.db as any)
          .prepare(
            `INSERT INTO revoked_credentials (jti, reason, expires_at)
         VALUES (?, ?, ?)
         ON CONFLICT (jti) DO NOTHING`,
          )
          .run(jti, opts.reason ?? null, opts.credentialExp?.toISOString() ?? null);
      })
      .immediate();
    /* eslint-enable @typescript-eslint/no-explicit-any */

    this.cache.add(jti);
  }

  /**
   * Startup cache warm-up. Non-fatal if the table doesn't exist yet.
   */
  async loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>> {
    let rows: Array<{ jti: string; expires_at: string | null }>;
    try {
      rows = this.db.prepare(`SELECT jti, expires_at FROM revoked_credentials`).all() as Array<{
        jti: string;
        expires_at: string | null;
      }>;
    } catch {
      // Table may not exist if initialize() hasn't run yet. Return empty.
      return [];
    }

    const result: Array<{ jti: string; credentialExp?: Date }> = [];
    for (const row of rows) {
      this.cache.add(row.jti);
      result.push({
        jti: row.jti,
        credentialExp: row.expires_at ? new Date(row.expires_at) : undefined,
      });
    }
    return result;
  }

  /**
   * Delete expired revocations (expires_at < beforeTs). Default: 30 days ago.
   * Evicts matching entries from the in-process cache. Returns count deleted.
   */
  async pruneExpired(beforeTs?: Date): Promise<number> {
    const cutoff = (beforeTs ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)).toISOString();

    const result = this.db
      .prepare(
        `DELETE FROM revoked_credentials
       WHERE expires_at IS NOT NULL AND expires_at < ?
       RETURNING jti`,
      )
      .all(cutoff) as Array<{ jti: string }>;

    for (const row of result) {
      this.cache.delete(row.jti);
    }

    return result.length;
  }
}
