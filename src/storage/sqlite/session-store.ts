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
 * SqliteSessionStore — SQLite implementation of SessionStore.
 *
 * SQLite adaptations: envelope as JSON TEXT, MAC as BLOB, expires_at as INTEGER
 * unix-ms, no read-through cache (single-process). Every put() MACs the envelope;
 * every get() verifies it — mismatch throws EnvelopeIntegrityError.
 *
 * Security: envelope rows are untrusted data. MAC verification closes the row-tamper gap —
 * a direct DB write cannot produce a valid envelope without the master key.
 * See envelope-mac.ts for the full threat model and rationale.
 */

import type { Database } from 'better-sqlite3';
import type { SessionStore, SessionEnvelope, SessionPutOptions } from '../types.js';
import { EnvelopeIntegrityError, EnvelopeTooLargeError, ProviderNotAllowedError } from '../types.js';
import { computeMac, verifyMac, MAX_ENVELOPE_BYTES } from '../envelope-mac.js';

export class SqliteSessionStore implements SessionStore {
  private readonly db: Database;
  private readonly macKey: Buffer;

  constructor(db: Database, macKey: Buffer) {
    if (!Buffer.isBuffer(macKey) || macKey.length === 0) {
      throw new Error('SqliteSessionStore: macKey must be a non-empty Buffer');
    }
    this.db = db;
    this.macKey = macKey;
  }

  // ─── get ────────────────────────────────────────────────────────────────

  async get(token: string): Promise<SessionEnvelope | null> {
    const now = Date.now();
    // expires_at filter in SQL avoids fetching already-expired rows.
    const row = (this.db as unknown as Database)
      .prepare(
        `SELECT envelope, mac, expires_at
         FROM sessions
        WHERE token = ?
          AND expires_at > ?`,
      )
      .get(token, now) as { envelope: string; mac: Buffer; expires_at: number } | undefined;

    if (!row) return null;

    const envelopeBytes = Buffer.byteLength(row.envelope, 'utf8');
    if (envelopeBytes > MAX_ENVELOPE_BYTES) {
      throw new EnvelopeTooLargeError(envelopeBytes, MAX_ENVELOPE_BYTES);
    }

    const envelope = JSON.parse(row.envelope) as SessionEnvelope;

    if (!verifyMac(envelope, row.mac, this.macKey)) {
      throw new EnvelopeIntegrityError();
    }

    return envelope;
  }

  // ─── put ────────────────────────────────────────────────────────────────

  async put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new Error('SqliteSessionStore.put: token must be a non-empty string');
    }
    if ((envelope.providerKind as string) === 'mock') {
      throw new ProviderNotAllowedError(
        envelope.oidcIssuer,
        'providerKind="mock" is not a valid persisted value',
      );
    }
    if (!Number.isFinite(opts.ttlSeconds) || opts.ttlSeconds <= 0) {
      throw new Error('SqliteSessionStore.put: ttlSeconds must be > 0');
    }

    const now = Date.now();
    const effectiveEnvelope: SessionEnvelope = {
      ...envelope,
      createdAt: envelope.createdAt || now,
      expiresAt: now + opts.ttlSeconds * 1000,
    };

    const { mac } = computeMac(effectiveEnvelope, this.macKey);

    // Storing non-canonical JSON is intentional: MAC covers canonical encoding,
    // not this column. get() re-parses and re-canonicalizes before verifying.
    (this.db as unknown as Database)
      .prepare(
        `INSERT INTO sessions (token, envelope, mac, human_did, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (token) DO UPDATE
         SET envelope   = excluded.envelope,
             mac        = excluded.mac,
             human_did  = excluded.human_did,
             created_at = excluded.created_at,
             expires_at = excluded.expires_at`,
      )
      .run(
        token,
        JSON.stringify(effectiveEnvelope),
        mac,
        effectiveEnvelope.humanDid,
        effectiveEnvelope.createdAt,
        effectiveEnvelope.expiresAt,
      );
  }

  // ─── delete ─────────────────────────────────────────────────────────────

  async delete(token: string): Promise<void> {
    (this.db as unknown as Database).prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
  }

  async deleteByHumanDid(humanDid: string): Promise<number> {
    const result = (this.db as unknown as Database)
      .prepare(`DELETE FROM sessions WHERE human_did = ?`)
      .run(humanDid);
    return Number(result.changes ?? 0);
  }

  // ─── pruneExpired ───────────────────────────────────────────────────────

  async pruneExpired(beforeTs?: Date, limit?: number): Promise<number> {
    const cutoff = (beforeTs ?? new Date()).getTime();
    if (limit !== undefined) {
      const result = (this.db as unknown as Database)
        .prepare(
          `DELETE FROM sessions
          WHERE token IN (
            SELECT token FROM sessions WHERE expires_at < ? LIMIT ?
          )`,
        )
        .run(cutoff, limit);
      return Number(result.changes ?? 0);
    }
    const result = (this.db as unknown as Database)
      .prepare(`DELETE FROM sessions WHERE expires_at < ?`)
      .run(cutoff);
    return Number(result.changes ?? 0);
  }
}
