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

import { describe, it, expect } from 'vitest';
import {
  LocalTrustAnchorStore,
  createTrustAnchorStore,
  type TrustAnchor,
} from '../src/discovery/trust-anchor.js';
import type { KeystoreBackend } from '../src/identity/keystore.js';

// ─── Mock Keystore ────────────────────────────────────────────────────────────

function makeKeystore(initial: Record<string, string> = {}): KeystoreBackend {
  const store: Record<string, string> = { ...initial };
  return {
    async read(key: string) {
      return store[key] ?? null;
    },
    async write(key: string, value: string) {
      store[key] = value;
    },
    async delete(key: string) {
      delete store[key];
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const OWN_DID = 'did:key:z6MkownServerAbc123';
const PEER_DID_1 = 'did:key:z6MkpeerOne111111';
const PEER_DID_2 = 'did:key:z6MkpeerTwo222222';

// ─── Constructor ──────────────────────────────────────────────────────────────

describe('LocalTrustAnchorStore — constructor', () => {
  it('own DID is trusted immediately after construction', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('own DID has source "local" and label "self"', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const anchors = store.list();
    const own = anchors.find((a) => a.did === OWN_DID);
    expect(own?.source).toBe('local');
    expect(own?.label).toBe('self');
  });

  it('unknown DID is not trusted after construction', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('throws TypeError if ownServerDid is empty', () => {
    expect(() => new LocalTrustAnchorStore({ ownServerDid: '' })).toThrow(TypeError);
  });

  it('throws TypeError if ownServerDid is not a string', () => {
    expect(() => new LocalTrustAnchorStore({ ownServerDid: null as unknown as string })).toThrow(
      TypeError,
    );
  });

  it('loads initialTrustedServers on construction', () => {
    // Session 7 / ABXAGNTS-244: replaces the prior `AGENTS_TRUSTED_SERVERS`
    // env-driven shape. Library no longer reads env directly; consumers pass
    // the parsed list in via the constructor option.
    const store = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      initialTrustedServers: [PEER_DID_1, PEER_DID_2],
    });
    expect(store.isTrusted(PEER_DID_1)).toBe(true);
    expect(store.isTrusted(PEER_DID_2)).toBe(true);
  });

  it('initialTrustedServers DIDs have source "env" (label preserved for audit-trail)', () => {
    const store = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      initialTrustedServers: [PEER_DID_1],
    });
    const anchor = store.list().find((a) => a.did === PEER_DID_1);
    expect(anchor?.source).toBe('env');
  });

  it('initialTrustedServers: skips empty entries (consumer-trimmed slack)', () => {
    // Even though resolveTrustedServersFromEnv() drops empties at the boundary,
    // the constructor still defends against malformed arrays passed in directly.
    const store = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      initialTrustedServers: [PEER_DID_1, '', '  ', '\t'],
    });
    expect(store.list().length).toBe(2); // own DID + PEER_DID_1
  });

  it('initialTrustedServers does not override own DID (local stays authoritative)', () => {
    const store = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      initialTrustedServers: [OWN_DID],
    });
    const own = store.list().find((a) => a.did === OWN_DID);
    // Should remain 'local' source even though it appears in initialTrustedServers too
    expect(own?.source).toBe('local');
  });

  it('does NOT honor AGENTS_TRUSTED_SERVERS env var (library no longer reads it)', () => {
    // Drift-prevention regression for ABXAGNTS-244. Two-direction assertion
    // (matches the -248 hardening pattern):
    //
    //   (a) env set, no initialTrustedServers passed → store has only own DID.
    //       Catches a regression that re-reads env when initialTrustedServers
    //       is undefined.
    //   (b) env set AND initialTrustedServers passed → store has only the DIDs
    //       from the option, NOT the env-only DID. Catches a regression that
    //       merges env content with the explicit option.
    //
    // Together these pin "the env var has zero behavioral effect on the store."
    const orig = process.env.AGENTS_TRUSTED_SERVERS;
    process.env.AGENTS_TRUSTED_SERVERS = `${PEER_DID_2}`;
    try {
      // (a) env-only — env content must NOT leak in.
      const storeA = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
      expect(storeA.list().length).toBe(1); // own DID only
      expect(storeA.isTrusted(PEER_DID_2)).toBe(false);

      // (b) explicit option AND env set — env content must NOT merge in.
      const storeB = new LocalTrustAnchorStore({
        ownServerDid: OWN_DID,
        initialTrustedServers: [PEER_DID_1],
      });
      expect(storeB.list().length).toBe(2); // own DID + PEER_DID_1
      expect(storeB.isTrusted(PEER_DID_1)).toBe(true);
      expect(storeB.isTrusted(PEER_DID_2)).toBe(false); // env-only DID stays out
    } finally {
      if (orig === undefined) delete process.env.AGENTS_TRUSTED_SERVERS;
      else process.env.AGENTS_TRUSTED_SERVERS = orig;
    }
  });
});

// ─── addTrustedServer ─────────────────────────────────────────────────────────

describe('addTrustedServer', () => {
  it('makes the DID trusted', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    expect(store.isTrusted(PEER_DID_1)).toBe(true);
  });

  it('emits "server-discovered" for a new DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const events: TrustAnchor[] = [];
    store.on('server-discovered', (a) => events.push(a));
    await store.addTrustedServer(PEER_DID_1, 'api', 'peer one');
    expect(events).toHaveLength(1);
    expect(events[0]?.did).toBe(PEER_DID_1);
    expect(events[0]?.source).toBe('api');
    expect(events[0]?.label).toBe('peer one');
  });

  it('does NOT emit "server-discovered" for an already-known DID (idempotent)', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const events: TrustAnchor[] = [];
    store.on('server-discovered', (a) => events.push(a));
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.addTrustedServer(PEER_DID_1, 'api'); // second call — idempotent
    expect(events).toHaveLength(1); // only fired once
  });

  it('throws TypeError for empty DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.addTrustedServer('', 'api')).rejects.toThrow(TypeError);
  });

  it('throws TypeError for non-string DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.addTrustedServer(null as unknown as string, 'api')).rejects.toThrow(
      TypeError,
    );
  });

  it('stores the label when provided', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api', 'Finance Server');
    const anchor = store.list().find((a) => a.did === PEER_DID_1);
    expect(anchor?.label).toBe('Finance Server');
  });

  it('stores anchor without label when label is omitted', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    const anchor = store.list().find((a) => a.did === PEER_DID_1);
    expect(anchor?.label).toBeUndefined();
  });
});

// ─── removeTrustedServer ──────────────────────────────────────────────────────

describe('removeTrustedServer', () => {
  it('removes a trusted DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.removeTrustedServer(PEER_DID_1);
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('emits "server-removed" with the DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    const removed: string[] = [];
    store.on('server-removed', (did) => removed.push(did));
    await store.removeTrustedServer(PEER_DID_1);
    expect(removed).toEqual([PEER_DID_1]);
  });

  it('no-op and no event for absent DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const removed: string[] = [];
    store.on('server-removed', (did) => removed.push(did));
    await store.removeTrustedServer(PEER_DID_1); // never added
    expect(removed).toHaveLength(0);
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('throws when attempting to remove own server DID', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.removeTrustedServer(OWN_DID)).rejects.toThrow(
      /cannot remove own server DID/,
    );
  });

  it('own DID remains trusted after failed removal attempt', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    try {
      await store.removeTrustedServer(OWN_DID);
    } catch {
      /* expected */
    }
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });
});

// ─── isTrusted ────────────────────────────────────────────────────────────────

describe('isTrusted', () => {
  it('returns true for own DID', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('returns false for unknown DID', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('returns true after addTrustedServer', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    expect(store.isTrusted(PEER_DID_1)).toBe(true);
  });

  it('returns false after removeTrustedServer', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.removeTrustedServer(PEER_DID_1);
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });
});

// ─── list() ───────────────────────────────────────────────────────────────────

describe('list()', () => {
  it('returns at least the own DID anchor', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const anchors = store.list();
    expect(anchors.some((a) => a.did === OWN_DID)).toBe(true);
  });

  it('includes newly added DIDs', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.addTrustedServer(PEER_DID_2, 'api');
    const dids = store.list().map((a) => a.did);
    expect(dids).toContain(PEER_DID_1);
    expect(dids).toContain(PEER_DID_2);
  });

  it('does not include removed DIDs', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.removeTrustedServer(PEER_DID_1);
    expect(store.list().some((a) => a.did === PEER_DID_1)).toBe(false);
  });

  it('returns correct count', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.addTrustedServer(PEER_DID_2, 'api');
    expect(store.list().length).toBe(3); // own + 2 peers
  });
});

// ─── Keystore persistence ─────────────────────────────────────────────────────

describe('persist and load — keystore round-trip', () => {
  it('api anchors survive a store/load cycle', async () => {
    const ks = makeKeystore();
    const store1 = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store1.addTrustedServer(PEER_DID_1, 'api', 'Test Server');
    // Simulate restart with new store instance using same keystore
    const store2 = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store2.load();
    expect(store2.isTrusted(PEER_DID_1)).toBe(true);
    expect(store2.list().find((a) => a.did === PEER_DID_1)?.label).toBe('Test Server');
  });

  it('removed api anchors are not restored after load', async () => {
    const ks = makeKeystore();
    const store1 = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store1.addTrustedServer(PEER_DID_1, 'api');
    await store1.removeTrustedServer(PEER_DID_1);
    // Restart
    const store2 = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store2.load();
    expect(store2.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('env anchors are NOT persisted (source: env excluded from keystore write)', async () => {
    // Session 7 / ABXAGNTS-244 — anchors loaded via initialTrustedServers carry
    // source: 'env' for audit-trail continuity, but they are NOT written to the
    // keystore. After "restart" (re-construct without initialTrustedServers),
    // the previously env-loaded peer should be absent — only the own-DID
    // (source: 'local') should round-trip via persist/load.
    //
    // Pre-v0.10.0 this test set AGENTS_TRUSTED_SERVERS env directly. After the
    // env-read removal, the same exclusion invariant is now exercised through
    // the explicit ctor option (more honest about what's being tested).
    const ks = makeKeystore();
    const store1 = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      keystore: ks,
      initialTrustedServers: [PEER_DID_1],
    });
    expect(store1.isTrusted(PEER_DID_1)).toBe(true);
    expect(store1.list().find((a) => a.did === PEER_DID_1)?.source).toBe('env');

    await store1.persist(); // explicit flush — should NOT write env anchor

    // Restart with NO initialTrustedServers. PEER_DID_1 must be absent.
    const store2 = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store2.load();
    expect(store2.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('local (own DID) anchor is always present after load, regardless of keystore', async () => {
    const ks = makeKeystore();
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store.load();
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('corrupted keystore JSON does not throw — falls back to own DID + env', async () => {
    const ks = makeKeystore({ 'agents:trust-anchors': 'NOT_VALID_JSON' });
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await expect(store.load()).resolves.toBeUndefined();
    // Own DID still trusted
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('load() without keystore is a no-op', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.load()).resolves.toBeUndefined();
  });

  it('persisted api anchor with wrong source is filtered out on load', async () => {
    // Simulate a keystore entry where source is 'local' (tampered or migrated)
    // Only 'api' source anchors should be restored.
    const ks = makeKeystore({
      'agents:trust-anchors': JSON.stringify([
        { did: PEER_DID_1, source: 'local', addedAt: 0 }, // wrong source — skip
      ]),
    });
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID, keystore: ks });
    await store.load();
    expect(store.isTrusted(PEER_DID_1)).toBe(false);
  });
});

// ─── Event emitter ────────────────────────────────────────────────────────────

describe('EventEmitter interface', () => {
  it('is an EventEmitter (has .on, .emit, .off)', () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(typeof store.on).toBe('function');
    expect(typeof store.emit).toBe('function');
    expect(typeof store.off).toBe('function');
  });

  it('multiple listeners receive "server-discovered"', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const a: TrustAnchor[] = [];
    const b: TrustAnchor[] = [];
    store.on('server-discovered', (x) => a.push(x));
    store.on('server-discovered', (x) => b.push(x));
    await store.addTrustedServer(PEER_DID_1, 'api');
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
  });

  it('once() listener fires exactly once', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    let count = 0;
    store.once('server-discovered', () => {
      count++;
    });
    await store.addTrustedServer(PEER_DID_1, 'api');
    await store.addTrustedServer(PEER_DID_2, 'api');
    expect(count).toBe(1);
  });
});

// ─── createTrustAnchorStore factory ──────────────────────────────────────────

describe('createTrustAnchorStore — factory', () => {
  it('returns a LocalTrustAnchorStore instance', () => {
    const store = createTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store).toBeInstanceOf(LocalTrustAnchorStore);
  });

  it('each call returns an independent instance', () => {
    const a = createTrustAnchorStore({ ownServerDid: OWN_DID });
    const b = createTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(a).not.toBe(b);
  });

  it('own DID is trusted on the factory-created instance', () => {
    const store = createTrustAnchorStore({ ownServerDid: OWN_DID });
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });
});

// ─── Security invariants ──────────────────────────────────────────────────────

describe('security invariants', () => {
  it('own DID cannot be removed even if added again as api source', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    // Caller re-adds own DID as api source (unusual but possible)
    await store.addTrustedServer(OWN_DID, 'api');
    // Still should not be removable
    await expect(store.removeTrustedServer(OWN_DID)).rejects.toThrow(
      /cannot remove own server DID/,
    );
    expect(store.isTrusted(OWN_DID)).toBe(true);
  });

  it('multiple stores are independent — no shared state', async () => {
    const storeA = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const storeB = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await storeA.addTrustedServer(PEER_DID_1, 'api');
    expect(storeB.isTrusted(PEER_DID_1)).toBe(false);
  });

  it('list() returns a snapshot — mutating it does not affect the store', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    const anchors = store.list();
    const original = anchors.length;
    anchors.push({ did: PEER_DID_1, source: 'api', addedAt: 0 }); // mutate snapshot
    expect(store.list().length).toBe(original); // store unaffected
  });
});
