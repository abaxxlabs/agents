import { describe, it, expect, beforeEach } from 'vitest';
import { DidAliasRegistry, type DidAlias } from '#did/alias.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, createSigner } from '#auth/index.js';

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
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ...overrides,
    };
  }

  beforeEach(() => {
    registry = new DidAliasRegistry();
  });

  it('didsMatch returns true for aliased DIDs (old → new)', () => {
    registry.addAlias(makeAlias());
    expect(registry.didsMatch(oldDid, newDid)).toBe(true);
  });

  it('didsMatch returns false for expired aliases', () => {
    registry.addAlias(
      makeAlias({
        expiresAt: new Date(Date.now() - 1000),
      }),
    );
    expect(registry.didsMatch(oldDid, newDid)).toBe(false);
  });
});

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

  it('rejects migration credential with invalid signature', async () => {
    const jwt = await createMigrationCredential();
    const parts = jwt.split('.');
    parts[2] = parts[2].slice(0, -4) + 'XXXX';
    const tampered = parts.join('.');

    const result = await verifier.verify(tampered, { skipScopeCheck: true });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('INVALID_SIGNATURE');
  });
});
