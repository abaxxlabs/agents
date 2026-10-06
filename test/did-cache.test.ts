import { describe, it, expect, vi } from 'vitest';
import { DidCache } from '#did/cache.js';
import { asDid } from '#types/domain.js';

describe('DidCache', () => {
  it('set then get returns the value', () => {
    const cache = new DidCache('10m');
    const key = new Uint8Array([1, 2, 3]);
    cache.set(asDid('did:key:abc'), key);
    expect(cache.get(asDid('did:key:abc'))).toEqual(key);
  });

  it('get after TTL expires returns undefined', () => {
    const now = 1_700_000_000_000;
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(now);
    const cache = new DidCache('5m');
    const key = new Uint8Array([4, 5, 6]);

    try {
      cache.set(asDid('did:key:expired'), key);
      nowSpy.mockReturnValue(now + 5 * 60 * 1000 + 1);

      expect(cache.get(asDid('did:key:expired'))).toBeUndefined();
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('get returns undefined for a key that was never set', () => {
    const cache = new DidCache('10m');
    expect(cache.get(asDid('did:key:unknown'))).toBeUndefined();
  });

  it('clear removes all entries', () => {
    const cache = new DidCache('10m');
    cache.set(asDid('did:key:a'), new Uint8Array([1]));
    cache.set(asDid('did:key:b'), new Uint8Array([2]));
    cache.clear();
    expect(cache.get(asDid('did:key:a'))).toBeUndefined();
    expect(cache.get(asDid('did:key:b'))).toBeUndefined();
  });

  it('size reflects the number of cached entries', () => {
    const cache = new DidCache('10m');
    expect(cache.size).toBe(0);
    cache.set(asDid('did:key:a'), new Uint8Array([1]));
    expect(cache.size).toBe(1);
    cache.set(asDid('did:key:a'), new Uint8Array([2]));
    expect(cache.size).toBe(1);
  });
});
