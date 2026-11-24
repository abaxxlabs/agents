import { describe, it, expect, beforeEach } from 'vitest';
import { DidAliasRegistry, type DidAlias } from '#did/alias.js';

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

  it('alias at exact expiry boundary is treated as expired', () => {
    const now = new Date();
    registry.addAlias(makeAlias({ expiresAt: now }));

    expect(registry.didsMatch(oldDid, newDid)).toBe(false);
    expect(registry.resolveToNew(oldDid)).toBe(oldDid);
    expect(registry.resolveToOld(newDid)).toBeUndefined();
  });
});
