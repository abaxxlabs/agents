import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { InMemorySessionStore } from '#storage/memory/session-store.js';
import { SqliteStorageBackend } from '#storage/sqlite/index.js';
import { deriveSessionMacKey } from '#storage/envelope-mac.js';
import { asMasterKey } from '#crypto/master-key.js';
import {
  EnvelopeTooLargeError,
  ProviderNotAllowedError,
  type SessionStore,
  type SessionEnvelope,
} from '#storage/types.js';

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

/**
 * Factory matrix — each entry yields (store, cleanup). Add rows as new
 * adapters ship.
 */
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

    it('put() rejects providerKind="mock"', async () => {
      await expect(
        store.put(
          't-m',
          { ...env(), providerKind: 'mock' as unknown as SessionEnvelope['providerKind'] },
          { ttlSeconds: 60 },
        ),
      ).rejects.toThrow(ProviderNotAllowedError);
    });

    it('put() rejects > 32KB canonical envelope', async () => {
      const huge = Array.from({ length: 1000 }, (_, _i) => 'g' + 'x'.repeat(50));
      await expect(
        store.put('t-big', env({ oidcGroupClaims: huge }), { ttlSeconds: 60 }),
      ).rejects.toThrow(EnvelopeTooLargeError);
    });

    it('get() returns null for unknown token', async () => {
      expect(await store.get('nope')).toBeNull();
    });

    it('get() is pure-read — no sliding-window TTL', async () => {
      await store.put('t-pure', env(), { ttlSeconds: 60 });
      const first = await store.get('t-pure');
      await new Promise((r) => setTimeout(r, 20));
      const second = await store.get('t-pure');
      expect(first!.expiresAt).toBe(second!.expiresAt);
    });

    it('delete() is idempotent on unknown token', async () => {
      await store.delete('never-there'); // must not throw
    });

    it('deleteByHumanDid returns accurate count', async () => {
      await store.put('a1', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
      await store.put('a2', env({ humanDid: 'did:a' }), { ttlSeconds: 60 });
      await store.put('b1', env({ humanDid: 'did:b' }), { ttlSeconds: 60 });
      expect(await store.deleteByHumanDid('did:a')).toBe(2);
      expect(await store.deleteByHumanDid('did:a')).toBe(0);
      expect(await store.get('b1')).not.toBeNull();
    });

    it('pruneExpired returns accurate count', async () => {
      await store.put('p1', env(), { ttlSeconds: 0.01 });
      await store.put('p2', env(), { ttlSeconds: 60 });
      await new Promise((r) => setTimeout(r, 30));
      const n = await store.pruneExpired();
      expect(n).toBe(1);
    });
  });
}
