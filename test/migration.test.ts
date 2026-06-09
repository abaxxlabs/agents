import { describe, it, expect, beforeEach } from 'vitest';
import { DidAliasRegistry, type DidAlias } from '#did/alias.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, createSigner } from '#auth/index.js';
import { IDENTITY_MIGRATION_CREDENTIAL } from '#types/index.js';

// ─── DidAliasRegistry Tests ───────────────────────────────────

describe('DidAliasRegistry', () => {
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
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
      ...overrides,
    };
  }

  beforeEach(() => {
    registry = new DidAliasRegistry();
  });

  it('didsMatch returns true for identical DIDs without aliases', () => {
    expect(registry.didsMatch('did:key:z6MkA', 'did:key:z6MkA')).toBe(true);
  });

  it('didsMatch returns false for different DIDs without aliases', () => {
    expect(registry.didsMatch('did:key:z6MkA', 'did:key:z6MkB')).toBe(false);
  });

  it('didsMatch returns true for aliased DIDs (old → new)', () => {
    registry.addAlias(makeAlias());
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
  });

  it('didsMatch returns true for aliased DIDs (new → old)', () => {
    registry.addAlias(makeAlias());
    expect(registry.didsMatch(newDid, oldDid)).toBe(true);
  });

  it('didsMatch returns false for expired aliases', () => {
    registry.addAlias(
      makeAlias({
        expiresAt: new Date(Date.now() - 1000), // expired
      }),
    );
    expect(registry.didsMatch(oldDid, newDid)).toBe(false);
  });

  it('resolveToNew returns new DID for active alias', () => {
    registry.addAlias(makeAlias());
    expect(registry.resolveToNew(oldDid)).toBe(newDid);
  });

  it('resolveToNew returns input DID when no alias exists', () => {
    expect(registry.resolveToNew('did:key:z6MkUnknown')).toBe('did:key:z6MkUnknown');
  });

  it('resolveToOld returns old DID for active alias', () => {
    registry.addAlias(makeAlias());
    expect(registry.resolveToOld(newDid)).toBe(oldDid);
  });

  it('resolveToOld returns undefined when no alias exists', () => {
    expect(registry.resolveToOld('did:key:z6MkUnknown')).toBeUndefined();
  });

  it('allEquivalentDids returns both DIDs for aliased identity', () => {
    registry.addAlias(makeAlias());
    const fromOld = registry.allEquivalentDids(oldDid);
    expect(fromOld).toContain(oldDid);
    expect(fromOld).toContain(newDid);
    expect(fromOld).toHaveLength(2);

    const fromNew = registry.allEquivalentDids(newDid);
    expect(fromNew).toContain(oldDid);
    expect(fromNew).toContain(newDid);
    expect(fromNew).toHaveLength(2);
  });

  it('allEquivalentDids returns single DID when no alias', () => {
    const result = registry.allEquivalentDids('did:key:z6MkSolo');
    expect(result).toEqual(['did:key:z6MkSolo']);
  });

  it('hasCredential detects already-processed migration', () => {
    registry.addAlias(makeAlias({ credentialHash: 'hash123' }));
    expect(registry.hasCredential('hash123')).toBe(true);
    expect(registry.hasCredential('unknown')).toBe(false);
  });

  it('loadAliases skips expired entries', () => {
    registry.loadAliases([
      makeAlias({ credentialHash: 'active', expiresAt: new Date(Date.now() + 86400000) }),
      makeAlias({
        oldDid: 'did:key:z6MkExpired',
        newDid: 'did:dht:EXPIRED',
        credentialHash: 'expired',
        expiresAt: new Date(Date.now() - 1000),
      }),
    ]);
    expect(registry.size).toBe(1);
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
    expect(registry.didsMatch('did:key:z6MkExpired', 'did:dht:EXPIRED')).toBe(false);
  });

  it('evictExpired removes expired aliases', () => {
    registry.addAlias(makeAlias({ expiresAt: new Date(Date.now() - 1000) }));
    expect(registry.size).toBe(1); // still in map (not evicted yet)
    const evicted = registry.evictExpired();
    expect(evicted).toBe(1);
    expect(registry.size).toBe(0);
  });
});

// ─── VcVerifier Migration Credential Detection Tests ──────────

describe('VcVerifier — IdentityMigrationCredential', () => {
  let verifier: VcVerifier;
  let tenantAdmin: ReturnType<typeof generateDidKey>;
  let newIdentity: ReturnType<typeof generateDidKey>;

  beforeEach(() => {
    tenantAdmin = generateDidKey();
    newIdentity = generateDidKey();

    verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
    verifier.registerKey(tenantAdmin.did, tenantAdmin.publicKey);
    verifier.registerKey(newIdentity.did, newIdentity.publicKey);
  });

  async function createMigrationCredential(overrides?: Record<string, unknown>): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: tenantAdmin.did,
      sub: newIdentity.did,
      iat: now,
      exp: now + 3600,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'IdentityMigrationCredential'],
        credentialSubject: {
          id: newIdentity.did,
          previousDid: 'did:key:z6MkOldIdentity',
          oidcSubject: 'user-123',
          migrationMethod: 'oidc-verified',
          oidcIssuer: 'https://login.microsoftonline.com/tenant-abc',
          migratedAt: new Date().toISOString(),
          ...overrides,
        },
      },
    };
    const signer = createSigner(tenantAdmin.privateKey);
    return signer.signJwt(payload);
  }

  it('detects IdentityMigrationCredential type and extracts claims', async () => {
    const jwt = await createMigrationCredential();
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(true);
    expect(result.status).toBe('MIGRATION_DETECTED');
    expect(result.credential?.migrationClaims).toBeDefined();
    expect(result.credential!.migrationClaims!.previousDid).toBe('did:key:z6MkOldIdentity');
    expect(result.credential!.migrationClaims!.oidcSubject).toBe('user-123');
    expect(result.credential!.migrationClaims!.migrationMethod).toBe('oidc-verified');
    expect(result.credential!.migrationClaims!.oidcIssuer).toBe(
      'https://login.microsoftonline.com/tenant-abc',
    );
  });

  it('rejects migration credential with missing previousDid', async () => {
    const jwt = await createMigrationCredential({ previousDid: undefined });
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('previousDid');
  });

  it('rejects migration credential with missing oidcSubject', async () => {
    const jwt = await createMigrationCredential({ oidcSubject: undefined });
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('oidcSubject');
  });

  it('rejects migration credential with invalid signature', async () => {
    const jwt = await createMigrationCredential();
    // Tamper with the JWT
    const parts = jwt.split('.');
    parts[2] = parts[2].slice(0, -4) + 'XXXX';
    const tampered = parts.join('.');

    const result = await verifier.verify(tampered, { skipScopeCheck: true });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('INVALID_SIGNATURE');
  });

  it('verifies subject binding on migration credential', async () => {
    const jwt = await createMigrationCredential();
    const result = await verifier.verify(jwt, {
      skipScopeCheck: true,
      expectedSubject: 'did:key:z6MkWrongAgent',
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('WRONG_SUBJECT');
  });

  it('detects migration credential inside a VP', async () => {
    const migrationJwt = await createMigrationCredential();

    // Wrap in a VP
    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-nonce-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [migrationJwt],
      },
    };
    const vpJwt = await agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('MIGRATION_DETECTED');
    expect(result.credential?.migrationClaims?.previousDid).toBe('did:key:z6MkOldIdentity');
  });
});

// ─── Alias-Aware Scope Engine DID Comparison ──────────────────

describe('Alias-aware DID comparison (ScopeEngine integration)', () => {
  it('IDENTITY_MIGRATION_CREDENTIAL constant is defined', () => {
    expect(IDENTITY_MIGRATION_CREDENTIAL).toBe('IdentityMigrationCredential');
  });
});
