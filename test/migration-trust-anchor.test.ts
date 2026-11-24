import { describe, it, expect } from 'vitest';
import {
  MigrationTrustAnchor,
  UntrustedMigrationIssuerError,
  asTrustedMigrationCredential,
} from '#discovery/migration-trust-anchor.js';

function makeJwt(iss: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss })).toString('base64url');
  return `${header}.${payload}.fakesig`;
}

describe('MigrationTrustAnchor', () => {
  it('isTrusted returns true after addFromParentCredentialChain', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:trusted');
    expect(anchor.isTrusted('did:dht:trusted')).toBe(true);
    expect(anchor.isTrusted('did:dht:other')).toBe(false);
  });

  it('rejects empty string DID', () => {
    const anchor = new MigrationTrustAnchor();
    expect(() => anchor.addFromParentCredentialChain('')).toThrow(TypeError);
    expect(anchor.list()).toHaveLength(0);
  });

  it('strips DID-URL fragment at insertion (stores bare DID)', () => {
    const anchor = new MigrationTrustAnchor();
    anchor.addFromParentCredentialChain('did:dht:abaxxone#key-1');
    expect(anchor.isTrusted('did:dht:abaxxone')).toBe(true);
    const entries = anchor.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.did).toBe('did:dht:abaxxone');
  });
});

describe('asTrustedMigrationCredential', () => {
  it('throws UntrustedMigrationIssuerError capturing the rejected DID', () => {
    const anchor = new MigrationTrustAnchor();
    const jwt = makeJwt('did:dht:fork-org');
    try {
      asTrustedMigrationCredential(jwt, anchor);
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(UntrustedMigrationIssuerError);
      expect((e as UntrustedMigrationIssuerError).issuerDid).toBe('did:dht:fork-org');
    }
  });
});
