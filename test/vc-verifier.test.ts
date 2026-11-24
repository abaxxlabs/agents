import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { createJwt } from '#crypto/jwt.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, issueCredential } from '#auth/index.js';

describe('VC Verifier', () => {
  describe('credential verification', () => {
    let verifier: VcVerifier;
    let human: ReturnType<typeof generateDidKey>;
    let agent: ReturnType<typeof generateDidKey>;

    beforeEach(() => {
      verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      human = generateDidKey();
      agent = generateDidKey();
      verifier.registerKey(human.did, human.publicKey);
      verifier.registerKey(agent.did, agent.publicKey);
    });

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
      expect(result.credential?.scope?.columns).toEqual(['patients.name', 'patients.dob']);
    });

    it('rejects expired credential', async () => {
      const nowMs = 1_800_000_000_000;
      const dateSpy = vi.spyOn(Date, 'now').mockReturnValue(nowMs);
      const jwt = await createJwt(
        {
          iss: human.did,
          sub: agent.did,
          iat: nowMs / 1000 - 3600,
          exp: nowMs / 1000 - 60,
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
      dateSpy.mockRestore();
    });

    it('rejects a VC without an expiration claim', async () => {
      const jwt = await createJwt(
        {
          iss: human.did,
          sub: agent.did,
          iat: Math.floor(Date.now() / 1000),
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
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toBe('Credential expiry (exp) is missing');
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

  describe('audience binding', () => {
    let verifier: VcVerifier;
    let issuer: ReturnType<typeof generateDidKey>;
    let agentA: ReturnType<typeof generateDidKey>;
    let agentB: ReturnType<typeof generateDidKey>;

    beforeEach(() => {
      verifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      issuer = generateDidKey();
      agentA = generateDidKey();
      agentB = generateDidKey();
      verifier.registerKey(issuer.did, issuer.publicKey);
      verifier.registerKey(agentA.did, agentA.publicKey);
      verifier.registerKey(agentB.did, agentB.publicKey);
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
  });
});

describe('SDK resolution — Ed25519 preference (partial fix, not kid-based selection)', () => {
  it.todo('selects by JWS kid and validates the assertionMethod relationship');
  it.todo('rejects a document whose only Ed25519 key is not authorised for assertions');
  it.todo('disambiguates a document containing two Ed25519 keys');
});

describe('did:dht offline resolution', () => {
  // Synthetic key pair generated for these tests; not from any environment.
  const DID = 'did:dht:jtm9ud15y8bqxsf4eub1efz7iz7yskxo3gjegccijdwfz8fcpd5y';
  const PUBLIC_KEY = 'TFf5jlsBwufYukTDJBb9rfoLKfDJkoMxlUjoW5ysaPY';

  function verifier(): VcVerifier {
    return new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
  }

  it('derives the identity key from the identifier with no resolver configured', async () => {
    const pk = await verifier().resolvePublicKey(DID);
    expect(Buffer.from(pk).toString('base64url')).toBe(PUBLIC_KEY);
    expect(pk.length).toBe(32);
  });
});
