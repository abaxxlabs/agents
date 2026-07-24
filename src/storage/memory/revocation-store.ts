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
 * Process-local RevocationStore with lazy and explicit expiry cleanup.
 */

import type { RevocationStore } from '../types.js';

interface RevocationEntry {
  revokedAt: string;
  reason?: string;
  credentialExpMs?: number;
}

export class InMemoryRevocationStore implements RevocationStore {
  private readonly store = new Map<string, RevocationEntry>();

  async isRevoked(jti: string): Promise<boolean> {
    const entry = this.store.get(jti);
    if (!entry) return false;

    if (entry.credentialExpMs !== undefined && entry.credentialExpMs < Date.now()) {
      this.store.delete(jti);
      return false;
    }

    return true;
  }

  async revoke(jti: string, opts: { reason?: string; credentialExp?: Date }): Promise<void> {
    if (!jti || typeof jti !== 'string') {
      throw new Error('RevocationStore.revoke: jti must be a non-empty string');
    }

    this.store.set(jti, {
      revokedAt: new Date().toISOString(),
      reason: opts.reason,
      credentialExpMs: opts.credentialExp?.getTime(),
    });
  }

  async loadAll(): Promise<Array<{ jti: string; credentialExp?: Date }>> {
    const result: Array<{ jti: string; credentialExp?: Date }> = [];
    for (const [jti, entry] of this.store.entries()) {
      result.push({
        jti,
        credentialExp:
          entry.credentialExpMs !== undefined ? new Date(entry.credentialExpMs) : undefined,
      });
    }
    return result;
  }

  async pruneExpired(beforeTs?: Date): Promise<number> {
    const cutoff = (beforeTs ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)).getTime();
    let count = 0;
    for (const [jti, entry] of this.store.entries()) {
      if (entry.credentialExpMs !== undefined && entry.credentialExpMs < cutoff) {
        this.store.delete(jti);
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
