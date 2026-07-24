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
 * PostgreSQL session envelopes with bounded read-through caching and
 * singleflight reads. Peer-instance deletions become visible after cache expiry.
 */

import type { Pool } from 'pg';
import type { SessionStore, SessionEnvelope, SessionPutOptions } from '../types.js';
import { EnvelopeIntegrityError, ProviderNotAllowedError } from '../types.js';
import { computeMac, verifyMac } from '../envelope-mac.js';

/** Read-through cache limits for PostgresSessionStore. */
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

  /** Insertion order provides bounded oldest-entry eviction. */
  private readonly cache = new Map<string, CacheEntry>();

  /** Per-token in-flight reads prevent duplicate database queries. */
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

  async get(token: string): Promise<SessionEnvelope | null> {
    const cached = this.cache.get(token);
    const now = Date.now();
    if (cached) {
      const cacheExpired = now - cached.cachedAt >= cached.effectiveTtlMs;
      const envelopeExpired = cached.envelope.expiresAt <= now;
      if (!cacheExpired && !envelopeExpired) {
        return cached.envelope;
      }
      this.cache.delete(token);
    }

    const inflight = this.singleflight.get(token);
    if (inflight) return inflight;

    const promise = this._fetchFromDb(token).finally(() => {
      if (this.singleflight.get(token) === promise) {
        this.singleflight.delete(token);
      }
    });
    this.singleflight.set(token, promise);
    return promise;
  }

  /** Reads PostgreSQL, verifies integrity, and populates the local cache. */
  private async _fetchFromDb(token: string): Promise<SessionEnvelope | null> {
    const result = await this.pool.query(
      `SELECT envelope, mac, expires_at
         FROM sessions
        WHERE token = $1
          AND expires_at > NOW()`,
      [token],
    );

    if (result.rows.length === 0) return null;
    const row = result.rows[0];

    const envelope: SessionEnvelope =
      typeof row.envelope === 'string' ? JSON.parse(row.envelope) : row.envelope;

    const dbExpiresMs = new Date(row.expires_at).getTime();

    if (!verifyMac(envelope, row.mac, this.macKey)) {
      throw new EnvelopeIntegrityError();
    }

    const now = Date.now();
    const envelopeTtl = Math.max(0, envelope.expiresAt - now);
    const dbTtl = Math.max(0, dbExpiresMs - now);
    const effectiveTtlMs = Math.min(this.cacheTtlMs, envelopeTtl, dbTtl);

    if (effectiveTtlMs > 0) {
      this._cachePut(token, envelope, effectiveTtlMs, now);
    }

    return envelope;
  }

  private _cachePut(
    token: string,
    envelope: SessionEnvelope,
    effectiveTtlMs: number,
    cachedAt: number,
  ): void {
    this.cache.delete(token);
    this.cache.set(token, { envelope, cachedAt, effectiveTtlMs });
    while (this.cache.size > this.cacheMax) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
  }

  async put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new Error('PostgresSessionStore.put: token must be a non-empty string');
    }
    if ((envelope.providerKind as string) === 'mock') {
      throw new ProviderNotAllowedError(
        envelope.oidcIssuer,
        'providerKind="mock" is not a valid persisted value',
      );
    }
    if (!Number.isFinite(opts.ttlSeconds) || opts.ttlSeconds <= 0) {
      throw new Error('PostgresSessionStore.put: ttlSeconds must be > 0');
    }

    const now = Date.now();
    const effectiveEnvelope: SessionEnvelope = {
      ...envelope,
      createdAt: envelope.createdAt || now,
      expiresAt: now + opts.ttlSeconds * 1000,
    };

    const { mac } = computeMac(effectiveEnvelope, this.macKey);

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

    this.cache.delete(token);
  }

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

  async pruneExpired(beforeTs?: Date, limit?: number): Promise<number> {
    const cutoff = beforeTs ?? new Date();
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

  /** Current cache size for tests and metrics. */
  get cacheSize(): number {
    return this.cache.size;
  }
}
