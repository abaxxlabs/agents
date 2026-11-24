import { describe, it, expect, vi } from 'vitest';
import { QueryAuthorizer } from '#sql/authorization.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, issueCredential, createSigner } from '#auth/index.js';
import { CredentialMalformedError } from '#errors/index.js';
import type { RegisteredAgent } from '#types/index.js';
import type { AgentStore } from '#storage/types.js';

function createFixtures() {
  const human = generateDidKey();
  const agentA = generateDidKey();
  const agentB = generateDidKey();

  const verifier = new VcVerifier({
    clockSkew: '30s',
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(agentA.did, agentA.publicKey);
  verifier.registerKey(agentB.did, agentB.publicKey);

  const agents = new Map<string, RegisteredAgent>([
    [
      agentA.did,
      {
        did: agentA.did,
        name: 'Agent A',
        ownerDid: human.did,
        signer: createSigner(agentA.privateKey),
        publicKey: agentA.publicKey,
      },
    ],
    [
      agentB.did,
      {
        did: agentB.did,
        name: 'Agent B',
        ownerDid: human.did,
        signer: createSigner(agentB.privateKey),
        publicKey: agentB.publicKey,
      },
    ],
  ]);

  const server = generateDidKey();
  verifier.registerKey(server.did, server.publicKey);

  const agentStore = {
    findByDid: vi.fn().mockResolvedValue(null),
    create: vi.fn(),
    list: vi.fn(),
    listAll: vi.fn(),
    count: vi.fn(),
  } as unknown as AgentStore;

  const authorizer = new QueryAuthorizer({
    verifier,
    agents,
    verifierDid: server.did,
    agentStore,
  });

  return { human, agentA, agentB, authorizer, agents };
}

describe('QueryAuthorizer', () => {
  it('resolves owner, read scope, and credential union for valid credentials', async () => {
    const { human, agentA, authorizer } = createFixtures();

    const cred1 = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const cred2 = await issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['patients.diagnosis'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const result = await authorizer.authorize({
      agent: agentA.did,
      credential: cred1,
      credentials: [cred2],
    });

    expect(result.ownerDid).toBe(human.did);
    expect(Array.from(result.readColumns).sort()).toEqual(
      ['patients.name', 'patients.dob', 'patients.diagnosis'].sort(),
    );
    expect(result.allJwts).toEqual([cred1, cred2]);
  });

  it('rejects a missing primary credential before verification', async () => {
    const { agentA, authorizer } = createFixtures();

    await expect(
      authorizer.authorize({ agent: agentA.did, credential: '' }),
    ).rejects.toBeInstanceOf(CredentialMalformedError);
  });
});
