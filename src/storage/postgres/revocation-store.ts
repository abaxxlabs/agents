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
 * Postgres implementation of RevocationStore. Durable JTI revocation with
 * in-process cache and configurable poll-based cross-instance coherency (default 30s).
 *
 * isRevoked() is plain SELECT (no lock). Same-process revoke() writes through to cache
 * immediately. Cross-instance staleness bounded by pollIntervalMs.
 * revoke() throws on any Postgres error — callers must treat rejection as a hard failure.
 */

import type { Pool } from 'pg';
import type { RevocationStore } from '../types.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

export interface PostgresRevocationStoreOptions {
  /**
   * Coherency mode for cross-instance cache invalidation.
   *
   * 'poll' (default): re-read all revocations from Postgres every pollIntervalMs.
   *   Works against any backing store; no Postgres-specific infrastructure needed.
   *
   * 'listen-notify': RESERVED FOR FUTURE USE — not implemented.
   *   Constructing the store with this mode throws. The type is preserved in
   *   the option shape so consumers can see the planned surface. Consumers
   *   who need tighter coherency bounds today should reduce pollIntervalMs.
   *
   * Operational note: 'poll' consumes one pool connection per pollIntervalMs cycle
   * for the SELECT * FROM revoked_credentials query.
   */
  mode?: 'poll' | 'listen-notify';

  /**
   * Poll interval in milliseconds. Only used when mode='poll'.
   * Default: 30_000 (30 seconds). This is the maximum cross-instance staleness
   * bound — a revocation performed on instance A is visible on instance B within
   * this window. Lower values reduce the staleness window at the cost of more
   * Postgres queries.
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

  /** Positive cache: JTI → expiry ms. Hot-path O(1) positive check. */
  private cache = new Map<string, { credentialExpMs?: number }>();

  /**
   * Negative cache: JTI → TTL expiry ms. Short-circuits DB on recent misses.
   * FIFO-bounded. Never consulted when positive cache hits.
   */
  private negativeCache = new Map<string, number>();

  /** Timer for the poll loop. Cleared on close(). */
  private pollTimer: ReturnType<typeof setInterval> | undefined;

  /** Whether the store has been closed. */
  private closed = false;

  constructor(pool: Pool, options: PostgresRevocationStoreOptions = {}, logger: Logger = getLogger()) {
    this.pool = pool;
    this.logger = logger;
    // Poll is the only implemented mode. listen-notify is kept in the option
    // type as a documented future mode, but is rejected here — silently
    // degrading would mislead callers who think they have tighter coherency
    // than they actually do.
    if (options.mode && options.mode !== 'poll') {
      throw new Error(
        `[PostgresRevocationStore] mode='${options.mode}' is not implemented in this release. ` +
          `Use mode='poll' (default). For tighter coherency bounds, reduce pollIntervalMs.`,
      );
    }
    this.pollIntervalMs = options.pollIntervalMs ?? 30_000;
  }

  /**
   * Start the background poll loop. Called by PostgresStorageBackend after initialize().
   * Idempotent — second call is a no-op.
   */
  startCoherency(): void {
    if (this.closed || this.pollTimer) return;

    this.pollTimer = setInterval(async () => {
      if (this.closed) return;
      try {
        await this._refreshCache();
      } catch (err) {
        // Non-fatal: poll failure means stale cache until next poll.
        // Log but don't throw — the coherency mechanism is advisory.
        this.logger.warn('[PostgresRevocationStore] Poll refresh failed', { error: err });
      }
    }, this.pollIntervalMs);

    // Allow Node.js to exit even if the interval is still running.
    // The process should not be kept alive by the poll loop alone.
    const timerWithUnref = this.pollTimer as { unref?: () => void } | undefined;
    if (timerWithUnref && typeof timerWithUnref.unref === 'function') {
      timerWithUnref.unref();
    }
  }

  /**
   * Stop the background coherency mechanism. Called by PostgresStorageBackend.close().
   */
  stopCoherency(): void {
    this.closed = true;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  /**
   * Hot path: positive cache → negative cache → DB SELECT.
   * Cross-instance false negatives bounded by pollIntervalMs.
   */
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
      // SQLSTATE 42P01: schema-missing → treat as no revocations (pre-migration boot).
      if (
        typeof err === 'object' &&
        err !== null &&
        'code' in err &&
        (err as { code: unknown }).code === '42P01'
      ) {
        return false; // don't cache — table may exist on the next call
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

  /** Insert/refresh a JTI in the negative cache. FIFO evict on overflow; delete+set for tail ordering. */
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

  /**
   * Revoke a JTI. Idempotent (ON CONFLICT DO NOTHING). Throws on any Postgres
   * error — callers MUST treat rejection as a hard failure.
   * Writes through to cache immediately; peers pick up on next poll.
   */
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

  /** Startup cache warm-up. Cold cache (DB unavailable) is non-fatal. */
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

  /**
   * Prune expired revocations. Default cutoff: 30 days ago.
   * NULL expires_at rows (non-expiring credentials) are never pruned.
   * Returns count deleted.
   */
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

  // ─── Internal ──────────────────────────────────────────────────────────────

  /**
   * Full cache refresh from Postgres. Drops negative entries for JTIs now
   * seen as positively revoked (prevents widening cross-instance staleness).
   */
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
