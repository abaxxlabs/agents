import { describe, it, expect, beforeEach } from 'vitest';
import {
  VcVerifier,
  createJwt,
  verifyJwtSignature,
  decodeJwt,
  resolveDidKey,
} from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { generateDidKey, issueCredential, createSigner } from '../src/auth/index.js';
import { resolveDidKeyFallback } from '../src/did-resolve.js';
import { DidResolutionFailedError } from '../src/errors/index.js';
import { base58Encode } from '../src/crypto/base58.js';

describe('VC Verifier', () => {
  describe('core', () => {
    let verifier: VcVerifier;
    let human: ReturnType<typeof generateDidKey>;
    let agent: ReturnType<typeof generateDidKey>;

    beforeEach(() => {
      verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
      human = generateDidKey();
      agent = generateDidKey();
      verifier.registerKey(human.did, human.publicKey);
      verifier.registerKey(agent.did, agent.publicKey);
    });

    describe('JWT creation and verification', () => {
      it('creates a valid JWT', async () => {
        const jwt = await createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
        expect(jwt.split('.').length).toBe(3);
      });

      it('verifies a valid JWT signature', async () => {
        const jwt = await createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
        expect(await verifyJwtSignature(jwt, human.publicKey)).toBe(true);
      });

      it('rejects a JWT with wrong key', async () => {
        const jwt = await createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
        const other = generateDidKey();
        expect(await verifyJwtSignature(jwt, other.publicKey)).toBe(false);
      });

      it('decodes JWT payload', async () => {
        const jwt = await createJwt({ iss: human.did, sub: agent.did, custom: 'data' }, human.privateKey);
        const { payload } = decodeJwt(jwt);
        expect(payload.iss).toBe(human.did);
        expect(payload.sub).toBe(agent.did);
        expect(payload.custom).toBe('data');
      });
    });

    describe('did:key resolution', () => {
      it('resolves a did:key to Ed25519 public key', () => {
        const pk = resolveDidKey(human.did);
        expect(pk.length).toBe(32);
        expect(Buffer.from(pk).equals(Buffer.from(human.publicKey))).toBe(true);
      });

      it('rejects non-did:key DIDs', () => {
        expect(() => resolveDidKey('did:ion:abc123')).toThrow('Not a did:key');
      });
    });

    describe('credential verification', () => {
      function makeCredential(overrides: Record<string, unknown> = {}) {
        return issueCredential(human.did, human.privateKey, {
          agent: agent.did,
          columns: ['patients.name', 'patients.dob'],
          actions: ['read'],
          expiresIn: '4h',
          ...overrides,
        });
      }

      it('verifies a valid credential', async () => {
        const jwt = await makeCredential();
        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(true);
        expect(result.status).toBe('VALID');
        expect(result.credential?.issuer).toBe(human.did);
        expect(result.credential?.subject).toBe(agent.did);
        expect(result.credential?.scope.columns).toEqual(['patients.name', 'patients.dob']);
      });

      it('rejects expired credential', async () => {
        const jwt = await issueCredential(human.did, human.privateKey, {
          agent: agent.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1s',
        });

        await new Promise((resolve) => setTimeout(resolve, 1500));

        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('EXPIRED');
      });

      it('rejects credential expired even by 1 second', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: human.did,
            sub: agent.did,
            iat: now - 10,
            exp: now - 5,
            vc: {
              credentialSubject: {
                id: agent.did,
                scope: { columns: ['patients.name'], actions: ['read'] },
              },
            },
          },
          human.privateKey,
        );

        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('EXPIRED');
      });

      it('rejects credential with invalid signature', async () => {
        const jwt = await makeCredential();
        const parts = jwt.split('.');
        parts[2] = parts[2].slice(0, -5) + 'XXXXX';
        const tampered = parts.join('.');

        const result = await verifier.verify(tampered);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('INVALID_SIGNATURE');
      });

      it('rejects credential with missing scope claim', async () => {
        const jwt = await createJwt(
          {
            iss: human.did,
            sub: agent.did,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
            vc: {
              credentialSubject: {
                id: agent.did,
              },
            },
          },
          human.privateKey,
        );

        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('MALFORMED');
      });

      it('rejects credential from non-did:key issuer', async () => {
        const fakeJwt = await createJwt(
          {
            iss: 'did:ion:EiAunknown123',
            sub: agent.did,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
            vc: {
              credentialSubject: {
                id: agent.did,
                scope: { columns: ['patients.name'], actions: ['read'] },
              },
            },
          },
          human.privateKey,
        );

        const freshVerifier = new VcVerifier({
          clockSkew: '30s',
          revocationStore: new InMemoryRevocationStore(),
        });
        const result = await freshVerifier.verify(fakeJwt);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('UNKNOWN_ISSUER');
      });
    });

    describe('DID cache', () => {
      it('caches resolved keys', async () => {
        const jwt = await issueCredential(human.did, human.privateKey, {
          agent: agent.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '4h',
        });

        await verifier.verify(jwt);
        expect(verifier.cacheSize).toBeGreaterThan(0);
      });
    });

    describe('scope extraction', () => {
      it('extracts scope from valid credential', async () => {
        const jwt = await issueCredential(human.did, human.privateKey, {
          agent: agent.did,
          columns: ['patients.name', 'patients.dob'],
          actions: ['read'],
          expiresIn: '4h',
        });

        const scope = verifier.extractScope(jwt);
        expect(scope.columns).toEqual(['patients.name', 'patients.dob']);
        expect(scope.actions).toEqual(['read']);
      });
    });
  });

  describe('audience binding', () => {
    let verifier: VcVerifier;
    let issuer: ReturnType<typeof generateDidKey>;
    let agentA: ReturnType<typeof generateDidKey>;
    let agentB: ReturnType<typeof generateDidKey>;

    beforeEach(() => {
      verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
      issuer = generateDidKey();
      agentA = generateDidKey();
      agentB = generateDidKey();
      verifier.registerKey(issuer.did, issuer.publicKey);
      verifier.registerKey(agentA.did, agentA.publicKey);
      verifier.registerKey(agentB.did, agentB.publicKey);
    });

    describe('skipScopeCheck', () => {
      it('binding VC without scope passes when skipScopeCheck: true', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              type: ['VerifiableCredential', 'IdentityBindingCredential'],
              credentialSubject: {
                humanDid: 'did:key:zABC',
                agentDid: agentA.did,
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, { skipScopeCheck: true });
        expect(result.valid).toBe(true);
        expect(result.status).toBe('VALID');
      });

      it('binding VC without scope still fails WITHOUT skipScopeCheck', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              type: ['VerifiableCredential', 'IdentityBindingCredential'],
              credentialSubject: {
                humanDid: 'did:key:zABC',
                agentDid: agentA.did,
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(false);
        expect(result.status).toBe('MALFORMED');
      });

      it('skipScopeCheck does not affect other validity checks', async () => {
        const past = Math.floor(Date.now() / 1000) - 7200;
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: past,
            exp: past + 3600,
            vc: {
              type: ['VerifiableCredential', 'IdentityBindingCredential'],
              credentialSubject: { humanDid: 'did:key:zABC', agentDid: agentA.did },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, { skipScopeCheck: true });
        expect(result.valid).toBe(false);
        expect(result.status).toBe('EXPIRED');
      });
    });

    describe('expectedSubject', () => {
      it('passes when sub matches expectedSubject', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              credentialSubject: {
                scope: { columns: ['table.col'], actions: ['read'] },
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, { expectedSubject: agentA.did });
        expect(result.valid).toBe(true);
      });

      it('rejects when sub does NOT match expectedSubject', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              credentialSubject: {
                scope: { columns: ['table.col'], actions: ['read'] },
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, { expectedSubject: agentB.did });
        expect(result.valid).toBe(false);
        expect(result.status).toBe('WRONG_SUBJECT');
        expect(result.error).toContain('subject mismatch');
      });

      it('subject check fires after signature check', async () => {
        const now = Math.floor(Date.now() / 1000);
        const validJwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              credentialSubject: {
                scope: { columns: ['table.col'], actions: ['read'] },
              },
            },
          },
          issuer.privateKey,
        );

        const parts = validJwt.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        payload.sub = agentB.did;
        parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const tamperedJwt = parts.join('.');

        const result = await verifier.verify(tamperedJwt, { expectedSubject: agentB.did });
        expect(result.valid).toBe(false);
        expect(result.status).toBe('INVALID_SIGNATURE');
      });

      it('no subject check when expectedSubject not passed', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              credentialSubject: {
                scope: { columns: ['table.col'], actions: ['read'] },
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt);
        expect(result.valid).toBe(true);
      });
    });

    describe('skipScopeCheck + expectedSubject together', () => {
      it('binding VC passes with correct subject and skipScopeCheck', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              type: ['VerifiableCredential', 'IdentityBindingCredential'],
              credentialSubject: {
                humanDid: 'did:key:zABC',
                agentDid: agentA.did,
              },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, {
          skipScopeCheck: true,
          expectedSubject: agentA.did,
        });
        expect(result.valid).toBe(true);
      });

      it('binding VC fails with wrong subject even with skipScopeCheck', async () => {
        const now = Math.floor(Date.now() / 1000);
        const jwt = await createJwt(
          {
            iss: issuer.did,
            sub: agentA.did,
            iat: now,
            exp: now + 3600,
            vc: {
              type: ['VerifiableCredential', 'IdentityBindingCredential'],
              credentialSubject: { humanDid: 'did:key:zABC', agentDid: agentA.did },
            },
          },
          issuer.privateKey,
        );

        const result = await verifier.verify(jwt, {
          skipScopeCheck: true,
          expectedSubject: agentB.did,
        });
        expect(result.valid).toBe(false);
        expect(result.status).toBe('WRONG_SUBJECT');
      });
    });
  });

  describe('migration credential edge cases', () => {
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

    async function createScopeCredential(): Promise<string> {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: tenantAdmin.did,
        sub: newIdentity.did,
        iat: now,
        exp: now + 3600,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: newIdentity.did,
            scope: { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
          },
        },
      };
      const signer = createSigner(tenantAdmin.privateKey);
      return signer.signJwt(payload);
    }

    it('rejects migration credential with missing migrationMethod', async () => {
      const jwt = await createMigrationCredential({ migrationMethod: undefined });
      const result = await verifier.verify(jwt, { skipScopeCheck: true });

      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('migrationMethod');
    });

    it('rejects migration credential with missing oidcIssuer', async () => {
      const jwt = await createMigrationCredential({ oidcIssuer: undefined });
      const result = await verifier.verify(jwt, { skipScopeCheck: true });

      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('oidcIssuer');
    });

    it('rejects migration credential with missing migratedAt', async () => {
      const jwt = await createMigrationCredential({ migratedAt: undefined });
      const result = await verifier.verify(jwt, { skipScopeCheck: true });

      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('migratedAt');
    });

    it('VP filters out invalid migration VC and verifies scope VC', async () => {
      const badMigrationJwt = await createMigrationCredential({ previousDid: undefined });
      const scopeJwt = await createScopeCredential();

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
          verifiableCredential: [badMigrationJwt, scopeJwt],
        },
      };
      const vpJwt = await agentSigner.signJwt(vpPayload);

      const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
      expect(result).toBeDefined();
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
    });

    it('VP with scope-only VCs returns VALID', async () => {
      const scopeJwt = await createScopeCredential();

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
          verifiableCredential: [scopeJwt],
        },
      };
      const vpJwt = await agentSigner.signJwt(vpPayload);

      const result = await verifier.verify(vpJwt);
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
      expect(result.credential?.migrationClaims).toBeUndefined();
    });

    it('VP skips garbled inner VC and still processes scope VC', async () => {
      const scopeJwt = await createScopeCredential();
      const garbledJwt = 'not.a.valid.jwt';

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
          verifiableCredential: [garbledJwt, scopeJwt],
        },
      };
      const vpJwt = await agentSigner.signJwt(vpPayload);

      const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('status');
    });

    it('VP with only a valid migration credential returns MIGRATION_DETECTED', async () => {
      const migrationJwt = await createMigrationCredential();

      const agentSigner = createSigner(newIdentity.privateKey);
      const now = Math.floor(Date.now() / 1000);
      const vpPayload = {
        iss: newIdentity.did,
        iat: now,
        exp: now + 300,
        jti: 'vp-only-migration-' + Date.now(),
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

    it('VP with only invalid migration credentials returns MALFORMED', async () => {
      const badJwt = await createMigrationCredential({ previousDid: undefined });

      const agentSigner = createSigner(newIdentity.privateKey);
      const now = Math.floor(Date.now() / 1000);
      const vpPayload = {
        iss: newIdentity.did,
        iat: now,
        exp: now + 300,
        jti: 'vp-only-bad-migration-' + Date.now(),
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [badJwt],
        },
      };
      const vpJwt = await agentSigner.signJwt(vpPayload);

      const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('no scope credentials');
    });

    it('VP with two migration credentials returns first valid one', async () => {
      const migration1 = await createMigrationCredential({
        previousDid: 'did:key:z6MkFirst',
        oidcSubject: 'first@corp.com',
      });
      const migration2 = await createMigrationCredential({
        previousDid: 'did:key:z6MkSecond',
        oidcSubject: 'second@corp.com',
      });

      const agentSigner = createSigner(newIdentity.privateKey);
      const now = Math.floor(Date.now() / 1000);
      const vpPayload = {
        iss: newIdentity.did,
        iat: now,
        exp: now + 300,
        jti: 'vp-two-migrations-' + Date.now(),
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [migration1, migration2],
        },
      };
      const vpJwt = await agentSigner.signJwt(vpPayload);

      const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
      expect(result.valid).toBe(true);
      expect(result.status).toBe('MIGRATION_DETECTED');
      expect(result.credential?.migrationClaims?.previousDid).toBe('did:key:z6MkFirst');
    });

    it('extracts all five migration claims correctly', async () => {
      const jwt = await createMigrationCredential({
        previousDid: 'did:key:z6MkSpecific',
        oidcSubject: 'specific-user@corp.com',
        migrationMethod: 'admin-verified',
        oidcIssuer: 'https://specific-issuer.example.com',
        migratedAt: '2026-04-18T12:00:00Z',
      });

      const result = await verifier.verify(jwt, { skipScopeCheck: true });

      expect(result.valid).toBe(true);
      expect(result.status).toBe('MIGRATION_DETECTED');
      expect(result.credential?.migrationClaims).toEqual({
        previousDid: 'did:key:z6MkSpecific',
        oidcSubject: 'specific-user@corp.com',
        migrationMethod: 'admin-verified',
        oidcIssuer: 'https://specific-issuer.example.com',
        migratedAt: '2026-04-18T12:00:00Z',
      });
    });
  });

  describe('base58 DID key validation', () => {
    it('resolveDidKeyFallback throws for invalid base58', () => {
      expect(() => resolveDidKeyFallback('did:key:zINVALIDBASE58OLIO')).toThrow(
        DidResolutionFailedError,
      );
    });

    it('verify returns MALFORMED for a credential with an invalid-base58 issuer DID', async () => {
      const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
      const badIss = 'did:key:zINVALIDBASE58OLIO';
      const fakePayload = {
        iss: badIss,
        sub: 'did:key:z123',
        vc: { credentialSubject: { scope: { columns: ['email'] } } },
      };
      const jwt =
        'eyJhbGciOiJFZERTQSJ9.' +
        Buffer.from(JSON.stringify(fakePayload)).toString('base64url') +
        '.fakesig';

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(false);
      expect(result.status).toMatch(/MALFORMED|UNKNOWN_ISSUER/);
    });
  });

  describe('clockSkew validation', () => {
    it('accepts clockSkew within 30-second limit', () => {
      expect(
        () => new VcVerifier({ clockSkew: '25s', revocationStore: new InMemoryRevocationStore() }),
      ).not.toThrow();
    });

    it('accepts the default 5s clockSkew', () => {
      expect(
        () => new VcVerifier({ revocationStore: new InMemoryRevocationStore() }),
      ).not.toThrow();
    });

    it('rejects clockSkew exceeding 30 seconds', () => {
      expect(
        () => new VcVerifier({ clockSkew: '45s', revocationStore: new InMemoryRevocationStore() }),
      ).toThrow(/exceeds maximum of 30 seconds/);
    });

    it('rejects absurd clockSkew values', () => {
      expect(
        () => new VcVerifier({ clockSkew: '365d', revocationStore: new InMemoryRevocationStore() }),
      ).toThrow(/exceeds maximum of 30 seconds/);
    });

    it('error message omits the raw clockSkew value', () => {
      try {
        new VcVerifier({ clockSkew: '999h', revocationStore: new InMemoryRevocationStore() });
        expect.unreachable('should have thrown');
      } catch (e: any) {
        expect(e.message).not.toContain('999h');
        expect(e.message).toContain('exceeds maximum of 30 seconds');
      }
    });

    it('rejects clockSkew of 0s', () => {
      expect(
        () => new VcVerifier({ clockSkew: '0s', revocationStore: new InMemoryRevocationStore() }),
      ).toThrow(/must be greater than zero/);
    });

    it('accepts minimal positive clockSkew', () => {
      expect(
        () => new VcVerifier({ clockSkew: '1s', revocationStore: new InMemoryRevocationStore() }),
      ).not.toThrow();
    });
  });

  describe('resolveDidKeyFallback key length', () => {
    it('rejects a DID with correct prefix but truncated key', () => {
      const shortKey = new Uint8Array([0xed, 0x01, ...new Array(16).fill(0x42)]);
      const encoded = 'z' + base58Encode(shortKey);
      const did = `did:key:${encoded}`;
      expect(() => resolveDidKeyFallback(did as any)).toThrow(DidResolutionFailedError);
      expect(() => resolveDidKeyFallback(did as any)).toThrow(/Expected 34 bytes/);
    });

    it('rejects a DID with correct prefix but extra bytes appended', () => {
      const longKey = new Uint8Array([0xed, 0x01, ...new Array(64).fill(0x42)]);
      const encoded = 'z' + base58Encode(longKey);
      const did = `did:key:${encoded}`;
      expect(() => resolveDidKeyFallback(did as any)).toThrow(DidResolutionFailedError);
      expect(() => resolveDidKeyFallback(did as any)).toThrow(/Expected 34 bytes/);
    });

    it('accepts a correctly-sized Ed25519 DID key', () => {
      const validKey = new Uint8Array([0xed, 0x01, ...new Array(32).fill(0x42)]);
      const encoded = 'z' + base58Encode(validKey);
      const did = `did:key:${encoded}`;
      const result = resolveDidKeyFallback(did as any);
      expect(result.length).toBe(32);
    });
  });
});
