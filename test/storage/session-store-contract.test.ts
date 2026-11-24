import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { InMemorySessionStore } from '#storage/memory/session-store.js';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
import { asMasterKey } from '#crypto/master-key.js';
import type { SessionStore, SessionEnvelope } from '#storage/types.js';

const _masterBuf = Buffer.alloc(32);
Buffer.from('contract-test-master', 'utf8').copy(_masterBuf);
const macKey = deriveSessionMacKey(asMasterKey(_masterBuf));

function env(overrides: Partial<SessionEnvelope> = {}): SessionEnvelope {
  return {
    humanDid: 'did:key:zContract',
    oidcIssuer: 'https://login.abaxx.one/realms/contract',
    oidcSubject: 'sub',
    providerKind: 'oidc-abaxx-one',
    createdAt: 0,
    expiresAt: 0,
    ...overrides,
  };
}

type Factory = () => Promise<{ store: SessionStore; cleanup: () => Promise<void> }>;

const factories: Array<{ name: string; factory: Factory }> = [
  {
    name: 'InMemorySessionStore',
    factory: async () => ({
      store: new InMemorySessionStore(macKey),
      cleanup: async () => undefined,
    }),
  },
  {
    name: 'SqliteSessionStore (:memory:)',
    factory: async () => {
      const backend = await SqliteStorageBackend.create(
        { type: 'sqlite', path: ':memory:', sessionMacKey: macKey },
        { sessionMacKey: macKey },
      );
      await backend.initialize();
      return {
        store: backend.sessions,
        cleanup: async () => {
          await backend.close();
        },
      };
    },
  },
];

for (const { name, factory } of factories) {
  describe(`SessionStore contract — ${name}`, () => {
    let store: SessionStore;
    let cleanup: () => Promise<void>;

    beforeEach(async () => {
      const created = await factory();
      store = created.store;
      cleanup = created.cleanup;
    });

    afterEach(async () => {
      await cleanup();
    });

    it('put + get round-trip', async () => {
      const oidcScopeClaims = {
        scope_columns: ['patients.name'],
        scope_actions: ['read'],
      };
      await store.put('t-1', env({ humanDid: 'did:a', oidcScopeClaims }), { ttlSeconds: 60 });
      const e = await store.get('t-1');
      expect(e).not.toBeNull();
      expect(e!.humanDid).toBe('did:a');
      expect(e!.oidcScopeClaims).toEqual(oidcScopeClaims);
      expect(e!.expiresAt).toBeGreaterThan(Date.now());
    });
  });
}
