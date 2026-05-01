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
 * In-process SessionStore. Zero-config default for consumers without a durable adapter.
 *
 * MAC verification runs even in-process for interface parity with durable adapters.
 * Process-local — sessions do not survive restart.
 * Lazy TTL eviction on get(); no sliding-window refresh.
 */

import type { SessionStore, SessionEnvelope, SessionPutOptions } from '../types.js';
import { ProviderNotAllowedError } from '../types.js';
import { computeMac, verifyMac } from '../envelope-mac.js';

interface InMemoryEntry {
  envelope: SessionEnvelope;
  mac: Buffer;
  humanDid: string; // denormalized for deleteByHumanDid parity with Postgres
}

export class InMemorySessionStore implements SessionStore {
  /** Map from token → entry. */
  private readonly store = new Map<string, InMemoryEntry>();
  private readonly macKey: Buffer;

  /**
   * @param macKey The HKDF-derived MAC key (from deriveSessionMacKey). Passed
   *   in rather than derived here so the caller owns the master-key loading
   *   path. Typically constructed once per process in the server's startup.
   */
  constructor(macKey: Buffer) {
    if (!Buffer.isBuffer(macKey) || macKey.length === 0) {
      throw new Error('InMemorySessionStore: macKey must be a non-empty Buffer');
    }
    this.macKey = macKey;
  }

  /**
   * Read an envelope by token. Returns null if not found or expired.
   * MAC verification runs on every read.
   */
  async get(token: string): Promise<SessionEnvelope | null> {
    const entry = this.store.get(token);
    if (!entry) return null;

    // Lazy expiry (TTL-only coherency)
    if (entry.envelope.expiresAt <= Date.now()) {
      this.store.delete(token);
      return null;
    }

    const ok = verifyMac(entry.envelope, entry.mac, this.macKey);
    if (!ok) {
      // Dynamically import to avoid circular exports at module-eval time.
      const { EnvelopeIntegrityError } = await import('../types.js');
      throw new EnvelopeIntegrityError();
    }

    return entry.envelope;
  }

  /**
   * Persist an envelope. Throws ProviderNotAllowedError for mock providers,
   * EnvelopeTooLargeError if canonical envelope exceeds 32KB.
   */
  async put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new Error('InMemorySessionStore.put: token must be a non-empty string');
    }
    // Mock providers are never persisted.
    if ((envelope.providerKind as string) === 'mock') {
      throw new ProviderNotAllowedError(
        envelope.oidcIssuer,
        'providerKind="mock" is not a valid persisted value',
      );
    }
    if (!Number.isFinite(opts.ttlSeconds) || opts.ttlSeconds <= 0) {
      throw new Error('InMemorySessionStore.put: ttlSeconds must be > 0');
    }

    // Compute authoritative expiresAt in the store.
    const now = Date.now();
    const effective: SessionEnvelope = {
      ...envelope,
      createdAt: envelope.createdAt || now,
      expiresAt: now + opts.ttlSeconds * 1000,
    };

    // computeMac canonicalizes, size-checks, and HMACs. Throws
    // EnvelopeTooLargeError or propagates any canonicalize error.
    const { mac } = computeMac(effective, this.macKey);
    this.store.set(token, {
      envelope: effective,
      mac,
      humanDid: effective.humanDid,
    });
  }

  /** Delete a session. Idempotent. */
  async delete(token: string): Promise<void> {
    this.store.delete(token);
  }

  /**
   * GDPR Art. 17 helper: delete all sessions for a human DID.
   * Returns count deleted.
   */
  async deleteByHumanDid(humanDid: string): Promise<number> {
    let count = 0;
    for (const [token, entry] of this.store) {
      if (entry.humanDid === humanDid) {
        this.store.delete(token);
        count++;
      }
    }
    return count;
  }

  /**
   * Prune expired entries. Default beforeTs = now.
   * Returns count deleted. limit bounds deletion to the first N matches.
   */
  async pruneExpired(beforeTs?: Date, limit?: number): Promise<number> {
    const cutoff = (beforeTs ?? new Date()).getTime();
    let count = 0;
    for (const [token, entry] of this.store) {
      if (limit !== undefined && count >= limit) break;
      if (entry.envelope.expiresAt < cutoff) {
        this.store.delete(token);
        count++;
      }
    }
    return count;
  }

  /** For testing: returns current size of the store. */
  get size(): number {
    return this.store.size;
  }
}
