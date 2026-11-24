import { describe, it, expect, beforeEach } from 'vitest';
import { InMemorySessionStore } from '#storage/memory/session-store.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
import { asMasterKey } from '#crypto/master-key.js';
import type { SessionEnvelope } from '#storage/types.js';

function env(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zAlice',
    oidcIssuer: 'https://login.abaxx.one/realms/demo',
    oidcSubject: 'alice',
    providerKind: 'oidc-abaxx-one',
    // The store replaces these placeholder timestamps.
    createdAt: 0,
    expiresAt: 0,
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

  it('get() returns null after expiry (TTL-only coherency)', async () => {
    await store.put('tok-1', env(), { ttlSeconds: 0.01 });
    await new Promise((r) => setTimeout(r, 30));
    expect(await store.get('tok-1')).toBeNull();
  });

  it('MAC mismatch throws EnvelopeIntegrityError (defense in depth)', async () => {
    await store.put('tok-dm', env(), { ttlSeconds: 60 });
    const internal = (store as unknown as { store: Map<string, { envelope: SessionEnvelope }> })
      .store;
    const entry = internal.get('tok-dm')!;
    entry.envelope.humanDid = 'did:attacker';
    await expect(store.get('tok-dm')).rejects.toThrow('Session envelope integrity check failed');
  });
});
