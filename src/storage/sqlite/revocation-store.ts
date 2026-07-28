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
 * Single-process durable JTI revocation. BEGIN IMMEDIATE serializes concurrent
 * verification and revocation operations.
 */

import type { Database } from 'better-sqlite3';
import type { RevocationStore } from '../types.js';

export class SqliteRevocationStore implements RevocationStore {
  private readonly db: Database;

  // Explicit pruning avoids silently hiding a recorded revocation during lookup.
  private readonly cache = new Set<string>();

  constructor(db: Database) {
    this.db = db;
  }

  /** Checks the local cache, then SQLite under a write-reserving transaction. */
  async isRevoked(jti: string): Promise<boolean> {
    if (this.cache.has(jti)) return true;

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

  /** Idempotently revokes a JTI under a write-reserving transaction. */
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

  /** Loads current revocations into the local cache. */
  async loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>> {
    let rows: Array<{ jti: string; expires_at: string | null }>;
    try {
      rows = this.db.prepare(`SELECT jti, expires_at FROM revoked_credentials`).all() as Array<{
        jti: string;
        expires_at: string | null;
      }>;
    } catch {
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

  /** Deletes expired revocations and evicts them from the local cache. */
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
