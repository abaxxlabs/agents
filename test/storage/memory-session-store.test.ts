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

import { describe, it, expect, beforeEach } from 'vitest';
import { InMemorySessionStore } from '../../src/storage/memory/session-store.js';
import { deriveSessionMacKey } from '../../src/storage/envelope-mac.js';
import { asMasterKey } from '../../src/crypto/master-key.js';
import { ProviderNotAllowedError, type SessionEnvelope } from '../../src/storage/types.js';

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

  it('get() returns null for unknown token', async () => {
    expect(await store.get('no-such-token')).toBeNull();
  });

  it('put + get round-trips and fills lifecycle fields (NF-1)', async () => {
    const before = Date.now();
    await store.put('tok-1', env({ humanDid: 'did:key:zAlice' }), { ttlSeconds: 60 });
    const read = await store.get('tok-1');
    expect(read).not.toBeNull();
    expect(read!.humanDid).toBe('did:key:zAlice');
    expect(read!.createdAt).toBeGreaterThanOrEqual(before);
    // expiresAt should be ~60s ahead of createdAt
    expect(read!.expiresAt - read!.createdAt).toBeGreaterThanOrEqual(60_000 - 50);
    expect(read!.expiresAt - read!.createdAt).toBeLessThanOrEqual(60_000 + 50);
  });

  it('put() rejects providerKind="mock" (D12)', async () => {
    const badEnv = { ...env(), providerKind: 'mock' as unknown as SessionEnvelope['providerKind'] };
    await expect(store.put('tok-bad', badEnv, { ttlSeconds: 60 })).rejects.toThrow(
      ProviderNotAllowedError,
    );
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

  it('get() is pure-read: does NOT refresh expiresAt (NF-6)', async () => {
    await store.put('tok-1', env(), { ttlSeconds: 60 });
    const first = await store.get('tok-1');
    await new Promise((r) => setTimeout(r, 10));
    const second = await store.get('tok-1');
    expect(first!.expiresAt).toBe(second!.expiresAt);
  });

  it('get() returns null after expiry (TTL-only coherency)', async () => {
    await store.put('tok-1', env(), { ttlSeconds: 0.01 }); // 10ms
    await new Promise((r) => setTimeout(r, 30));
    expect(await store.get('tok-1')).toBeNull();
  });

  it('delete() is idempotent on unknown token', async () => {
    await store.delete('never-existed');
    // no throw = pass
  });

  it('delete() removes a persisted session', async () => {
    await store.put('tok-d', env(), { ttlSeconds: 60 });
    expect(await store.get('tok-d')).not.toBeNull();
    await store.delete('tok-d');
    expect(await store.get('tok-d')).toBeNull();
  });

  it('deleteByHumanDid() deletes all sessions for a DID and returns count (NF-9)', async () => {
    await store.put('t1', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await store.put('t2', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
    await store.put('t3', env({ humanDid: 'did:b' }), { ttlSeconds: 60 });

    const n = await store.deleteByHumanDid('did:a');
    expect(n).toBe(2);
    expect(await store.get('t1')).toBeNull();
    expect(await store.get('t2')).toBeNull();
    expect(await store.get('t3')).not.toBeNull();
  });

  it('pruneExpired() removes only expired rows and returns count (NF-5)', async () => {
    // Insert one that will expire, one that won't.
    await store.put('tok-expired', env(), { ttlSeconds: 0.01 });
    await store.put('tok-fresh', env(), { ttlSeconds: 60 });
    await new Promise((r) => setTimeout(r, 30));

    const n = await store.pruneExpired();
    expect(n).toBe(1);
    expect(await store.get('tok-expired')).toBeNull();
    expect(await store.get('tok-fresh')).not.toBeNull();
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
