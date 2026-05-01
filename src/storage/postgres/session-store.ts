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
 * Postgres implementation of SessionStore. Durable session envelopes with
 * per-instance read-through cache (default 10s TTL, 10k entries) and
 * singleflight coalescing for concurrent gets.
 *
 * Cross-instance coherency: TTL-only. delete() evicts local cache; peer caches
 * expire within readThroughCacheMs. MAC verified on cache-fill, not on every hit.
 * All methods throw on Postgres error — no silent fallback.
 */

import type { Pool } from 'pg';
import type { SessionStore, SessionEnvelope, SessionPutOptions } from '../types.js';
import { EnvelopeIntegrityError, ProviderNotAllowedError } from '../types.js';
import { computeMac, verifyMac } from '../envelope-mac.js';

/**
 * Options for PostgresSessionStore.
 *
 * Defaults are conservative:
 *   - 10s cache TTL: short enough that admin-revoke is effective
 *     cross-instance within a normal UX round-trip.
 *   - 10k cache entries: ~5MB RAM at typical envelope sizes; bounded to
 *     prevent memory pressure on unusually bursty auth traffic.
 */
export interface PostgresSessionStoreOptions {
  /** Per-instance read-through cache TTL. Default 10_000 (10s). */
  readThroughCacheMs?: number;
  /** Max cache entries before LRU eviction. Default 10_000. */
  readThroughCacheMax?: number;
}

interface CacheEntry {
  envelope: SessionEnvelope;
  cachedAt: number;
  effectiveTtlMs: number; // min(configured, envelope.expiresAt - cachedAt)
}

export class PostgresSessionStore implements SessionStore {
  private readonly pool: Pool;
  private readonly macKey: Buffer;
  private readonly cacheTtlMs: number;
  private readonly cacheMax: number;

  /**
   * Insertion-ordered Map used as a simple LRU: on cache size breach, we evict
   * the oldest entry (first map key). Good-enough for a 10k-bounded cache.
   */
  private readonly cache = new Map<string, CacheEntry>();

  /** Singleflight coalescer: per-token in-flight get() promises. */
  private readonly singleflight = new Map<string, Promise<SessionEnvelope | null>>();

  constructor(pool: Pool, macKey: Buffer, options: PostgresSessionStoreOptions = {}) {
    this.pool = pool;
    if (!Buffer.isBuffer(macKey) || macKey.length === 0) {
      throw new Error('PostgresSessionStore: macKey must be a non-empty Buffer');
    }
    this.macKey = macKey;
    this.cacheTtlMs = options.readThroughCacheMs ?? 10_000;
    this.cacheMax = options.readThroughCacheMax ?? 10_000;
  }

  // ─── get (hot path) ──────────────────────────────────────────────────────

  async get(token: string): Promise<SessionEnvelope | null> {
    // 1. Cache hit? Check both cache-TTL and envelope-expiry invariants.
    const cached = this.cache.get(token);
    const now = Date.now();
    if (cached) {
      const cacheExpired = now - cached.cachedAt >= cached.effectiveTtlMs;
      const envelopeExpired = cached.envelope.expiresAt <= now;
      if (!cacheExpired && !envelopeExpired) {
        return cached.envelope;
      }
      // Invariant: cache never authoritative on deletion/expiry — fall through.
      this.cache.delete(token);
    }

    // 2. Singleflight: one in-flight fetch per token.
    const inflight = this.singleflight.get(token);
    if (inflight) return inflight;

    const promise = this._fetchFromDb(token).finally(() => {
      // Clear the singleflight entry on resolution, success or failure.
      // Use == not === because a later _fetchFromDb for the same token may
      // have already replaced our entry.
      if (this.singleflight.get(token) === promise) {
        this.singleflight.delete(token);
      }
    });
    this.singleflight.set(token, promise);
    return promise;
  }

  /**
   * Internal: hit Postgres, verify MAC, populate cache.
   *
   * Throws EnvelopeIntegrityError on MAC mismatch. Throws on any Postgres
   * error.
   */
  private async _fetchFromDb(token: string): Promise<SessionEnvelope | null> {
    // Plain SELECT, no FOR UPDATE. expires_at check in SQL avoids fetching
    // rows we immediately discard.
    const result = await this.pool.query(
      `SELECT envelope, mac, expires_at
         FROM sessions
        WHERE token = $1
          AND expires_at > NOW()`,
      [token],
    );

    if (result.rows.length === 0) return null;
    const row = result.rows[0];

    // Parse envelope. pg driver returns JSONB as parsed object; handle both
    // for defensive compatibility (some pg-driver versions return text under
    // certain type-parser overrides).
    const envelope: SessionEnvelope =
      typeof row.envelope === 'string' ? JSON.parse(row.envelope) : row.envelope;

    // Normalize expiresAt from DB timestamptz to unix ms if envelope was
    // stored before the explicit expiresAt field convention. The canonical
    // case is envelope already has expiresAt; we only cross-check against
    // the DB column when computing cache TTL below.
    const dbExpiresMs = new Date(row.expires_at).getTime();

    // MAC verify. Mismatch is a tamper indicator, not an operational error.
    if (!verifyMac(envelope, row.mac, this.macKey)) {
      throw new EnvelopeIntegrityError();
    }

    // Populate cache. TTL = min(configured, envelope.expiresAt - now, dbExpires - now).
    // Using the tighter of envelope.expiresAt and dbExpiresMs covers both:
    //   - envelope says expired sooner than DB (shouldn't happen; defensive)
    //   - DB says expired sooner than envelope (also shouldn't; defensive)
    const now = Date.now();
    const envelopeTtl = Math.max(0, envelope.expiresAt - now);
    const dbTtl = Math.max(0, dbExpiresMs - now);
    const effectiveTtlMs = Math.min(this.cacheTtlMs, envelopeTtl, dbTtl);

    // Only cache if there's actually time left. A zero-TTL entry would be
    // immediately treated as a miss by the next get(), wasting a map slot.
    if (effectiveTtlMs > 0) {
      this._cachePut(token, envelope, effectiveTtlMs, now);
    }

    return envelope;
  }

  /** LRU-ish cache put: bound size by evicting oldest insertion on overflow. */
  private _cachePut(
    token: string,
    envelope: SessionEnvelope,
    effectiveTtlMs: number,
    cachedAt: number,
  ): void {
    // Refresh insertion order on re-put (delete + set).
    this.cache.delete(token);
    this.cache.set(token, { envelope, cachedAt, effectiveTtlMs });
    // Bound size. Map iteration is insertion order, so the first key is the
    // oldest entry.
    while (this.cache.size > this.cacheMax) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
  }

  // ─── put ────────────────────────────────────────────────────────────────

  async put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new Error('PostgresSessionStore.put: token must be a non-empty string');
    }
    // Mock providers are never persisted.
    if ((envelope.providerKind as string) === 'mock') {
      throw new ProviderNotAllowedError(
        envelope.oidcIssuer,
        'providerKind="mock" is not a valid persisted value',
      );
    }
    if (!Number.isFinite(opts.ttlSeconds) || opts.ttlSeconds <= 0) {
      throw new Error('PostgresSessionStore.put: ttlSeconds must be > 0');
    }

    // MAC is computed over the JS-computed expiresAt, not the DB-computed one.
    // For single-digit-second clock skew both values are identical modulo sub-second
    // resolution. Re-reading the DB value and re-MACing would halve write throughput.
    const now = Date.now();
    const effectiveEnvelope: SessionEnvelope = {
      ...envelope,
      createdAt: envelope.createdAt || now,
      expiresAt: now + opts.ttlSeconds * 1000,
    };

    const { mac } = computeMac(effectiveEnvelope, this.macKey);

    // INSERT ... ON CONFLICT updates existing rows (same token, re-issued
    // envelope or TTL refresh). We include human_did denormalized so
    // deleteByHumanDid can use an index. expires_at stored via make_interval
    // for DB-clock authority; on a multi-instance deployment with NTP skew,
    // the DB clock wins.
    await this.pool.query(
      `INSERT INTO sessions (token, envelope, mac, human_did, expires_at)
       VALUES ($1, $2::jsonb, $3, $4, NOW() + make_interval(secs => $5))
       ON CONFLICT (token) DO UPDATE
         SET envelope   = EXCLUDED.envelope,
             mac        = EXCLUDED.mac,
             human_did  = EXCLUDED.human_did,
             expires_at = EXCLUDED.expires_at`,
      [token, JSON.stringify(effectiveEnvelope), mac, effectiveEnvelope.humanDid, opts.ttlSeconds],
    );

    // Evict local cache — next get() re-reads and MAC-verifies from DB.
    this.cache.delete(token);
  }

  // ─── delete ─────────────────────────────────────────────────────────────

  async delete(token: string): Promise<void> {
    await this.pool.query(`DELETE FROM sessions WHERE token = $1`, [token]);
    this.cache.delete(token);
  }

  async deleteByHumanDid(humanDid: string): Promise<number> {
    const result = await this.pool.query(
      `DELETE FROM sessions WHERE human_did = $1 RETURNING token`,
      [humanDid],
    );
    for (const row of result.rows) {
      this.cache.delete(row.token);
    }
    return result.rows.length;
  }

  // ─── pruneExpired ───────────────────────────────────────────────────────

  async pruneExpired(beforeTs?: Date, limit?: number): Promise<number> {
    const cutoff = beforeTs ?? new Date();
    // LIMIT subselect so we can bound a single-call DELETE. Avoids million-
    // row locks on long-idle deployments accumulating expired sessions.
    const query = limit
      ? `DELETE FROM sessions WHERE token IN (
           SELECT token FROM sessions WHERE expires_at < $1 LIMIT $2
         ) RETURNING token`
      : `DELETE FROM sessions WHERE expires_at < $1 RETURNING token`;
    const params = limit ? [cutoff.toISOString(), limit] : [cutoff.toISOString()];
    const result = await this.pool.query(query, params);
    for (const row of result.rows) {
      this.cache.delete(row.token);
    }
    return result.rows.length;
  }

  // ─── Test/ops helpers ───────────────────────────────────────────────────

  /** For testing and metrics: current cache entry count. */
  get cacheSize(): number {
    return this.cache.size;
  }
}
