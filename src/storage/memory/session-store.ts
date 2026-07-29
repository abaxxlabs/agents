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
 * Process-local SessionStore with lazy expiry and MAC parity with durable adapters.
 */

import type { SessionStore, SessionEnvelope, SessionPutOptions } from '../types.js';
import { ProviderNotAllowedError } from '../types.js';
import { computeMac, verifyMac } from '../envelope-mac.js';

interface InMemoryEntry {
  envelope: SessionEnvelope;
  mac: Buffer;
  humanDid: string; // Denormalized for deleteByHumanDid.
}

export class InMemorySessionStore implements SessionStore {
  private readonly store = new Map<string, InMemoryEntry>();
  private readonly macKey: Buffer;

  /**
   * @param macKey The caller-derived session MAC key.
   */
  constructor(macKey: Buffer) {
    if (!Buffer.isBuffer(macKey) || macKey.length === 0) {
      throw new Error('InMemorySessionStore: macKey must be a non-empty Buffer');
    }
    this.macKey = macKey;
  }

  async get(token: string): Promise<SessionEnvelope | null> {
    const entry = this.store.get(token);
    if (!entry) return null;

    if (entry.envelope.expiresAt <= Date.now()) {
      this.store.delete(token);
      return null;
    }

    const ok = verifyMac(entry.envelope, entry.mac, this.macKey);
    if (!ok) {
      const { EnvelopeIntegrityError } = await import('../types.js');
      throw new EnvelopeIntegrityError();
    }

    return entry.envelope;
  }

  async put(token: string, envelope: SessionEnvelope, opts: SessionPutOptions): Promise<void> {
    if (!token || typeof token !== 'string') {
      throw new Error('InMemorySessionStore.put: token must be a non-empty string');
    }
    if ((envelope.providerKind as string) === 'mock') {
      throw new ProviderNotAllowedError(
        envelope.oidcIssuer,
        'providerKind="mock" is not a valid persisted value',
      );
    }
    if (!Number.isFinite(opts.ttlSeconds) || opts.ttlSeconds <= 0) {
      throw new Error('InMemorySessionStore.put: ttlSeconds must be > 0');
    }

    const now = Date.now();
    const effective: SessionEnvelope = {
      ...envelope,
      createdAt: envelope.createdAt || now,
      expiresAt: now + opts.ttlSeconds * 1000,
    };

    const { mac } = computeMac(effective, this.macKey);
    this.store.set(token, {
      envelope: effective,
      mac,
      humanDid: effective.humanDid,
    });
  }

  async delete(token: string): Promise<void> {
    this.store.delete(token);
  }

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

  /** Current entry count for tests. */
  get size(): number {
    return this.store.size;
  }
}
