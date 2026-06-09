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

import { parseDuration } from '#config.js';
import type { Did } from '#types/domain.js';

interface CacheEntry {
  publicKey: Uint8Array;
  resolvedAt: number;
}

/** TTL-based cache for resolved DID public keys. */
export class DidCache {
  private cache = new Map<string, CacheEntry>();
  private ttlMs: number;

  constructor(ttl = '5m') {
    this.ttlMs = parseDuration(ttl);
  }

  get(did: Did): Uint8Array | undefined {
    const entry = this.cache.get(did);
    if (!entry) return undefined;
    if (Date.now() - entry.resolvedAt > this.ttlMs) {
      this.cache.delete(did);
      return undefined;
    }
    return entry.publicKey;
  }

  set(did: Did, publicKey: Uint8Array): void {
    this.cache.set(did, { publicKey, resolvedAt: Date.now() });
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}
