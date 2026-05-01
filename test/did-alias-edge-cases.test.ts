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
 * DID Alias Registry — Edge Case Tests
 *
 * Tests the expiry edge cases for resolveToNew, resolveToOld, and
 * allEquivalentDids that are not covered by the main migration.test.ts.
 * These paths matter because expired aliases silently returning stale data
 * would be a security issue — an old DID should NOT resolve after expiry.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DidAliasRegistry, type DidAlias } from '../src/did-alias.js';

describe('DidAliasRegistry — expiry edge cases', () => {
  let registry: DidAliasRegistry;
  const oldDid = 'did:key:z6MkOLD';
  const newDid = 'did:dht:NEW';

  function makeAlias(overrides?: Partial<DidAlias>): DidAlias {
    return {
      oldDid,
      newDid,
      credentialHash: 'abc123',
      oidcSubject: 'user@example.com',
      oidcIssuer: 'https://login.example.com',
      migratedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ...overrides,
    };
  }

  beforeEach(() => {
    registry = new DidAliasRegistry();
  });

  // ─── resolveToNew: expired alias ────────────────────────────────

  it('resolveToNew returns input DID when alias is expired', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() - 1000) }));
    // Should NOT resolve to the new DID — the alias has expired.
    expect(registry.resolveToNew(oldDid)).toBe(oldDid);
  });

  // ─── resolveToOld: expired alias ────────────────────────────────

  it('resolveToOld returns undefined when alias is expired', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() - 1000) }));
    // Should NOT resolve — the alias has expired.
    expect(registry.resolveToOld(newDid)).toBeUndefined();
  });

  // ─── allEquivalentDids: expired alias ───────────────────────────

  it('allEquivalentDids returns single DID when alias is expired (lookup from old)', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() - 1000) }));
    const result = registry.allEquivalentDids(oldDid);
    // Should return only the input DID, not expand to both.
    expect(result).toEqual([oldDid]);
  });

  it('allEquivalentDids returns single DID when alias is expired (lookup from new)', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() - 1000) }));
    const result = registry.allEquivalentDids(newDid);
    expect(result).toEqual([newDid]);
  });

  // ─── Multiple aliases ───────────────────────────────────────────

  it('handles multiple aliases without cross-contamination', () => {
    const oldDid2 = 'did:key:z6MkOLD2';
    const newDid2 = 'did:dht:NEW2';
    registry.addAlias(makeAlias());
    registry.addAlias(
      makeAlias({
        oldDid: oldDid2,
        newDid: newDid2,
        credentialHash: 'other-hash',
      }),
    );

    // Each alias pair should resolve independently
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
    expect(registry.didsMatch(oldDid2, newDid2)).toBe(true);
    // Cross-pair should NOT match
    expect(registry.didsMatch(oldDid, newDid2)).toBe(false);
    expect(registry.didsMatch(oldDid2, newDid)).toBe(false);

    expect(registry.size).toBe(2);
  });

  // ─── evictExpired: mix of expired and active ────────────────────

  it('evictExpired keeps active aliases while removing expired ones', () => {
    registry.addAlias(
      makeAlias({
        oldDid: 'did:key:z6MkExpired',
        newDid: 'did:dht:EXPIRED',
        credentialHash: 'expired-hash',
        expiresAt: new Date(Date.now() - 1000),
      }),
    );
    registry.addAlias(makeAlias()); // still active

    expect(registry.size).toBe(2);
    const evicted = registry.evictExpired();
    expect(evicted).toBe(1);
    expect(registry.size).toBe(1);
    // Active alias still works
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
    // Expired alias should be gone
    expect(registry.didsMatch('did:key:z6MkExpired', 'did:dht:EXPIRED')).toBe(false);
  });

  it('evictExpired returns 0 when no aliases are expired', () => {
    registry.addAlias(makeAlias());
    const evicted = registry.evictExpired();
    expect(evicted).toBe(0);
    expect(registry.size).toBe(1);
  });

  // ─── hasCredential: multiple aliases ────────────────────────────

  it('hasCredential scans across all aliases', () => {
    registry.addAlias(makeAlias({ credentialHash: 'hash-A' }));
    registry.addAlias(
      makeAlias({
        oldDid: 'did:key:z6MkOther',
        newDid: 'did:dht:OTHER',
        credentialHash: 'hash-B',
      }),
    );

    expect(registry.hasCredential('hash-A')).toBe(true);
    expect(registry.hasCredential('hash-B')).toBe(true);
    expect(registry.hasCredential('hash-C')).toBe(false);
  });

  // ─── Chain migration: A → B → C ───────────────────────────────

  it('chain migration: A→B then B→C, didsMatch resolves each hop', () => {
    const didA = 'did:key:z6MkAAAA';
    const didB = 'did:dht:BBBB';
    const didC = 'did:dht:CCCC';

    registry.addAlias(makeAlias({ oldDid: didA, newDid: didB, credentialHash: 'h1' }));
    registry.addAlias(makeAlias({ oldDid: didB, newDid: didC, credentialHash: 'h2' }));

    // Direct hops resolve
    expect(registry.didsMatch(didA, didB)).toBe(true);
    expect(registry.didsMatch(didB, didC)).toBe(true);
    // Transitive: A→C does NOT resolve (by design, no transitive closure)
    expect(registry.didsMatch(didA, didC)).toBe(false);
  });

  it('chain migration: allEquivalentDids only returns one hop', () => {
    const didA = 'did:key:z6MkAAAA';
    const didB = 'did:dht:BBBB';
    const didC = 'did:dht:CCCC';

    registry.addAlias(makeAlias({ oldDid: didA, newDid: didB, credentialHash: 'h1' }));
    registry.addAlias(makeAlias({ oldDid: didB, newDid: didC, credentialHash: 'h2' }));

    expect(registry.allEquivalentDids(didA)).toEqual([didA, didB]);
    // didB is both a newDid (from A→B) and an oldDid (from B→C).
    // oldToNew is checked first, so B→C wins.
    expect(registry.allEquivalentDids(didB)).toEqual([didB, didC]);
    expect(registry.allEquivalentDids(didC)).toEqual([didB, didC]);
  });

  // ─── Alias overwrite (same oldDid, different newDid) ───────────

  it('second alias for same oldDid overwrites the first in memory', () => {
    const newDid2 = 'did:dht:SECOND';
    registry.addAlias(makeAlias());
    registry.addAlias(makeAlias({ newDid: newDid2, credentialHash: 'hash-2' }));

    // The second alias overwrites — oldDid now maps to newDid2
    expect(registry.didsMatch(oldDid, newDid2)).toBe(true);
    // First mapping is broken in memory
    expect(registry.didsMatch(oldDid, newDid)).toBe(false);
    // But size reflects only unique oldDid keys
    expect(registry.size).toBe(1);
  });

  // ─── Alias expiry boundary (exact moment) ─────────────────────

  it('alias at exact expiry boundary is treated as expired', () => {
    const now = new Date();
    registry.addAlias(makeAlias({ expiresAt: now }));

    // expiresAt <= now means expired (strict inequality in the code)
    expect(registry.didsMatch(oldDid, newDid)).toBe(false);
    expect(registry.resolveToNew(oldDid)).toBe(oldDid);
    expect(registry.resolveToOld(newDid)).toBeUndefined();
  });

  it('alias 1ms before expiry is still active', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() + 1) }));
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
  });
});
