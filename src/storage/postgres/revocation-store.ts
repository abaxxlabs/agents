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
 * PostgreSQL revocations with an in-process cache and poll-bounded
 * cross-instance coherency.
 */

import type { Pool } from 'pg';
import type { RevocationStore } from '../types.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

export interface PostgresRevocationStoreOptions {
  /**
   * Cache-coherency mode. listen-notify is reserved and rejected at construction.
   */
  mode?: 'poll' | 'listen-notify';

  /**
   * Poll interval and maximum cross-instance staleness. Defaults to 30 seconds.
   */
  pollIntervalMs?: number;
}

/** 60s negative-result cache TTL. Cross-instance worst-case staleness: pollIntervalMs + 60s. */
const NEGATIVE_CACHE_TTL_MS = 60_000;

/** FIFO cap on negative cache entries. Map insertion order makes FIFO cheap. */
const NEGATIVE_CACHE_MAX_ENTRIES = 10_000;

export class PostgresRevocationStore implements RevocationStore {
  private readonly pool: Pool;
  private readonly pollIntervalMs: number;
  private readonly logger: Logger;

  /** Positive cache: JTI to credential expiry. */
  private cache = new Map<string, { credentialExpMs?: number }>();

  /** FIFO-bounded negative cache: JTI to cache expiry. */
  private negativeCache = new Map<string, number>();

  private pollTimer: ReturnType<typeof setInterval> | undefined;

  private closed = false;

  constructor(
    pool: Pool,
    options: PostgresRevocationStoreOptions = {},
    logger: Logger = getLogger(),
  ) {
    this.pool = pool;
    this.logger = logger;
    if (options.mode && options.mode !== 'poll') {
      throw new Error(
        `[PostgresRevocationStore] mode='${options.mode}' is not implemented in this release. ` +
          `Use mode='poll' (default). For tighter coherency bounds, reduce pollIntervalMs.`,
      );
    }
    this.pollIntervalMs = options.pollIntervalMs ?? 30_000;
  }

  /** Idempotently starts cross-instance cache polling. */
  startCoherency(): void {
    if (this.closed || this.pollTimer) return;

    this.pollTimer = setInterval(async () => {
      if (this.closed) return;
      try {
        await this._refreshCache();
      } catch (err) {
        this.logger.warn('[PostgresRevocationStore] Poll refresh failed', { error: err });
      }
    }, this.pollIntervalMs);

    const timerWithUnref = this.pollTimer as { unref?: () => void } | undefined;
    if (timerWithUnref && typeof timerWithUnref.unref === 'function') {
      timerWithUnref.unref();
    }
  }

  /** Stops cross-instance cache polling. */
  stopCoherency(): void {
    this.closed = true;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  /** Checks positive cache, negative cache, then PostgreSQL. */
  async isRevoked(jti: string): Promise<boolean> {
    if (this.cache.has(jti)) return true;

    const negativeUntilMs = this.negativeCache.get(jti);
    if (negativeUntilMs !== undefined) {
      if (negativeUntilMs > Date.now()) {
        return false;
      }
      this.negativeCache.delete(jti);
    }

    let result;
    try {
      result = await this.pool.query(`SELECT 1 FROM revoked_credentials WHERE jti = $1`, [jti]);
    } catch (err) {
      if (
        typeof err === 'object' &&
        err !== null &&
        'code' in err &&
        (err as { code: unknown }).code === '42P01'
      ) {
        return false; // The table may exist on the next call.
      }
      throw err;
    }

    if (result.rows.length > 0) {
      this.cache.set(jti, {});
      return true;
    }

    this.recordNegative(jti);
    return false;
  }

  /** Inserts a negative result with FIFO eviction. */
  private recordNegative(jti: string): void {
    if (this.negativeCache.size >= NEGATIVE_CACHE_MAX_ENTRIES && !this.negativeCache.has(jti)) {
      const oldestKey = this.negativeCache.keys().next().value;
      if (oldestKey !== undefined) {
        this.negativeCache.delete(oldestKey);
      }
    }
    this.negativeCache.delete(jti);
    this.negativeCache.set(jti, Date.now() + NEGATIVE_CACHE_TTL_MS);
  }

  /** Idempotently revokes a JTI and updates the local cache. */
  async revoke(jti: string, opts: { reason?: string; credentialExp?: Date }): Promise<void> {
    if (!jti || typeof jti !== 'string') {
      throw new Error('RevocationStore.revoke: jti must be a non-empty string');
    }

    await this.pool.query(
      `INSERT INTO revoked_credentials (jti, reason, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (jti) DO NOTHING`,
      [jti, opts.reason ?? null, opts.credentialExp?.toISOString() ?? null],
    );

    this.cache.set(jti, {
      credentialExpMs: opts.credentialExp?.getTime(),
    });
    this.negativeCache.delete(jti);
  }

  /** Loads current revocations into the local cache. */
  async loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>> {
    const result = await this.pool.query(`SELECT jti, expires_at FROM revoked_credentials`);

    const entries: Array<{ jti: string; credentialExp?: Date }> = [];
    for (const row of result.rows) {
      const credentialExp = row.expires_at ? new Date(row.expires_at) : undefined;
      this.cache.set(row.jti, { credentialExpMs: credentialExp?.getTime() });
      entries.push({ jti: row.jti, credentialExp });
    }

    return entries;
  }

  /** Prunes expiring credentials older than the cutoff; null expiry is retained. */
  async pruneExpired(beforeTs?: Date): Promise<number> {
    const cutoff = beforeTs ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const result = await this.pool.query(
      `DELETE FROM revoked_credentials
       WHERE expires_at IS NOT NULL AND expires_at < $1
       RETURNING jti`,
      [cutoff.toISOString()],
    );

    for (const row of result.rows) {
      this.cache.delete(row.jti);
      this.negativeCache.delete(row.jti);
    }

    return result.rows.length;
  }

  /** Replaces the positive cache and clears contradictory negative entries. */
  private async _refreshCache(): Promise<void> {
    const result = await this.pool.query(`SELECT jti, expires_at FROM revoked_credentials`);

    const newCache = new Map<string, { credentialExpMs?: number }>();
    for (const row of result.rows) {
      newCache.set(row.jti, {
        credentialExpMs: row.expires_at ? new Date(row.expires_at).getTime() : undefined,
      });
      this.negativeCache.delete(row.jti);
    }
    this.cache = newCache;
  }
}
