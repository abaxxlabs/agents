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

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DidCache } from '../src/vc-verifier.js';

describe('DidCache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('set then get returns the value', () => {
    const cache = new DidCache('10m');
    const key = new Uint8Array([1, 2, 3]);
    cache.set('did:key:abc', key);
    expect(cache.get('did:key:abc')).toEqual(key);
  });

  it('get after TTL expires returns undefined', () => {
    const cache = new DidCache('5m');
    const key = new Uint8Array([4, 5, 6]);
    cache.set('did:key:expired', key);

    vi.advanceTimersByTime(5 * 60 * 1000 + 1);

    expect(cache.get('did:key:expired')).toBeUndefined();
  });

  it('clear() empties the cache', () => {
    const cache = new DidCache('10m');
    cache.set('did:key:a', new Uint8Array([1]));
    cache.set('did:key:b', new Uint8Array([2]));
    expect(cache.size).toBe(2);

    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get('did:key:a')).toBeUndefined();
  });

  it('size property reflects entry count', () => {
    const cache = new DidCache('10m');
    expect(cache.size).toBe(0);

    cache.set('did:key:one', new Uint8Array([1]));
    expect(cache.size).toBe(1);

    cache.set('did:key:two', new Uint8Array([2]));
    expect(cache.size).toBe(2);

    cache.set('did:key:one', new Uint8Array([10]));
    expect(cache.size).toBe(2);
  });

  it('get on a missing key returns undefined', () => {
    const cache = new DidCache('10m');
    expect(cache.get('did:key:nonexistent')).toBeUndefined();
  });
});
