import { describe, it, expect, beforeEach } from 'vitest';
import { InMemorySessionStore } from '../../src/storage/memory/session-store.js';
import { deriveSessionMacKey } from '../../src/storage/envelope-mac.js';
import { asMasterKey } from '../../src/crypto/master-key.js';
import type { SessionEnvelope } from '../../src/storage/types.js';

function env(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zAlice',
    oidcIssuer: 'https://login.abaxx.one/realms/demo',
    oidcSubject: 'alice',
    providerKind: 'oidc-abaxx-one',
    createdAt: 0, // overridden by store
    expiresAt: 0, // overridden by store
    ...overrides,
  };
}

describe('InMemorySessionStore', () => {
  const masterBuf = Buffer.alloc(32);
  Buffer.from('test-master', 'utf8').copy(masterBuf);
  const macKey = deriveSessionMacKey(asMasterKey(masterBuf));
  let store: InMemorySessionStore;

  beforeEach(() => {
    store = new InMemorySessionStore(macKey);
  });

  it('put() rejects empty token', async () => {
    await expect(store.put('', env(), { ttlSeconds: 60 })).rejects.toThrow(
      'token must be a non-empty string',
    );
  });

  it('put() rejects non-positive ttlSeconds', async () => {
    await expect(store.put('tok', env(), { ttlSeconds: 0 })).rejects.toThrow(
      'ttlSeconds must be > 0',
    );
    await expect(store.put('tok', env(), { ttlSeconds: -1 })).rejects.toThrow(
      'ttlSeconds must be > 0',
    );
  });

  it('get() returns null after expiry (TTL-only coherency)', async () => {
    await store.put('tok-1', env(), { ttlSeconds: 0.01 }); // 10ms
    await new Promise((r) => setTimeout(r, 30));
    expect(await store.get('tok-1')).toBeNull();
  });

  it('delete() removes a persisted session', async () => {
    await store.put('tok-d', env(), { ttlSeconds: 60 });
    expect(await store.get('tok-d')).not.toBeNull();
    await store.delete('tok-d');
    expect(await store.get('tok-d')).toBeNull();
  });

  it('pruneExpired(limit) bounds deletion to first N expired rows', async () => {
    for (let i = 0; i < 5; i++) {
      await store.put(`tok-${i}`, env(), { ttlSeconds: 0.01 });
    }
    await new Promise((r) => setTimeout(r, 30));
    const n = await store.pruneExpired(undefined, 2);
    expect(n).toBe(2);
  });

  it('MAC mismatch throws EnvelopeIntegrityError (defense in depth)', async () => {
    await store.put('tok-dm', env(), { ttlSeconds: 60 });
    // Directly mutate internal map entry to simulate memory corruption.
    const internal = (store as unknown as { store: Map<string, { envelope: SessionEnvelope }> })
      .store;
    const entry = internal.get('tok-dm')!;
    entry.envelope.humanDid = 'did:attacker';
    await expect(store.get('tok-dm')).rejects.toThrow('Session envelope integrity check failed');
  });
});
