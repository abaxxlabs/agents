import { randomUUID } from 'node:crypto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { decodeJwt, createJwt } from '../src/jwt-utils.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '../src/auth/index.js';

function setup() {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();
  const subWorker = generateDidKey();

  const verifier = new VcVerifier({
    revocationStore: new InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(supervisor.did, supervisor.publicKey);
  verifier.registerKey(worker.did, worker.publicKey);
  verifier.registerKey(subWorker.did, subWorker.publicKey);

  return { human, supervisor, worker, subWorker, verifier };
}

describe('Re-delegation is not permitted', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it('issueDelegatedCredential succeeds when source is an AgentScopeCredential (root)', async () => {
    const { human, supervisor, worker } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const delegated = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      rootCred,
      decodeJwt(rootCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    const decoded = decodeJwt(delegated).payload;
    expect(decoded.vc?.type).toContain('DelegatedAgentScopeCredential');
    expect(Array.isArray(decoded.delegationChain)).toBe(true);
    expect(decoded.delegationChain).toHaveLength(1);
  });

  it('issueDelegatedCredential throws when source is itself a DelegatedAgentScopeCredential', async () => {
    const { human, supervisor, worker, subWorker } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      rootCred,
      decodeJwt(rootCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    await expect(
      issueDelegatedCredential(
        worker.did,
        createSigner(worker.privateKey),
        workerCred,
        decodeJwt(workerCred).payload.jti!,
        { columns: ['patients.name'], actions: ['read'] },
        {
          targetAgent: subWorker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      ),
    ).rejects.toThrow(/re-delegation is not permitted/i);
  });

  it('verifier rejects a credential whose delegationChain parent is itself a DelegatedAgentScopeCredential', async () => {
    const { human, supervisor, worker, subWorker, verifier } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      rootCred,
      decodeJwt(rootCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    // Hand-craft a re-delegated credential to bypass the issuance guard so we
    // can prove the verifier rejects it on the read path too.
    const now = Math.floor(Date.now() / 1000);
    const reDelegatedPayload = {
      iss: worker.did,
      sub: subWorker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [workerCred],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
        credentialSubject: {
          id: subWorker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: worker.did,
          grantedTo: subWorker.did,
          delegatedGrantId: decodeJwt(workerCred).payload.jti!,
          delegated: false,
        },
      },
    };
    const reDelegatedCred = await createJwt(reDelegatedPayload, worker.privateKey);

    const result = await verifier.verify(reDelegatedCred, {
      expectedSubject: subWorker.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/re-delegated/i);
  });

  it('issueDelegatedCredential rejects when source has scalar string vc.type DelegatedAgentScopeCredential', async () => {
    const { human, supervisor, worker, subWorker } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const rootJti = decodeJwt(rootCred).payload.jti!;

    // Hand-craft a JWT with vc.type as a scalar string to bypass Array.isArray
    const now = Math.floor(Date.now() / 1000);
    const craftedPayload = {
      iss: supervisor.did,
      sub: worker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: 'DelegatedAgentScopeCredential',
        credentialSubject: {
          id: worker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: supervisor.did,
          grantedTo: worker.did,
          delegatedGrantId: rootJti,
          delegated: false,
        },
      },
    };
    const craftedJwt = await createJwt(craftedPayload, supervisor.privateKey);

    await expect(
      issueDelegatedCredential(
        worker.did,
        createSigner(worker.privateKey),
        craftedJwt,
        decodeJwt(craftedJwt).payload.jti!,
        { columns: ['patients.name'], actions: ['read'] },
        {
          targetAgent: subWorker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      ),
    ).rejects.toThrow(/re-delegation is not permitted/i);
  });

  it('verifier rejects when delegationChain ancestor has scalar string vc.type DelegatedAgentScopeCredential', async () => {
    const { human, supervisor, worker, subWorker, verifier } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Craft an ancestor JWT with scalar vc.type
    const now = Math.floor(Date.now() / 1000);
    const craftedAncestor = {
      iss: supervisor.did,
      sub: worker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: 'DelegatedAgentScopeCredential',
        credentialSubject: {
          id: worker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: supervisor.did,
          grantedTo: worker.did,
          delegatedGrantId: decodeJwt(rootCred).payload.jti!,
          delegated: false,
        },
      },
    };
    const craftedAncestorJwt = await createJwt(craftedAncestor, supervisor.privateKey);

    // Build a child credential with the crafted ancestor in its chain
    const reDelegatedPayload = {
      iss: worker.did,
      sub: subWorker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [craftedAncestorJwt],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
        credentialSubject: {
          id: subWorker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: worker.did,
          grantedTo: subWorker.did,
          delegatedGrantId: decodeJwt(craftedAncestorJwt).payload.jti!,
          delegated: false,
        },
      },
    };
    const reDelegatedCred = await createJwt(reDelegatedPayload, worker.privateKey);

    const result = await verifier.verify(reDelegatedCred, {
      expectedSubject: subWorker.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/re-delegated/i);
  });

  it('verifier recognizes DelegatedAgentScopeCredential from scalar vc.type at top level', async () => {
    const { human, supervisor, worker, verifier } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Scalar vc.type DelegatedAgentScopeCredential with a valid chain —
    // should be recognized as delegated type and pass structural checks.
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: supervisor.did,
      sub: worker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: 'DelegatedAgentScopeCredential',
        credentialSubject: {
          id: worker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: supervisor.did,
          grantedTo: worker.did,
          delegatedGrantId: decodeJwt(rootCred).payload.jti!,
          delegated: false,
        },
      },
    };
    const jwt = await createJwt(payload, supervisor.privateKey);

    const result = await verifier.verify(jwt, { expectedSubject: worker.did });

    expect(result.valid).toBe(true);
    expect(result.credential?.vcTypes).toContain('DelegatedAgentScopeCredential');
  });

  it('verifier rejects a credential declared as DelegatedAgentScopeCredential with no delegationChain', async () => {
    const { worker, subWorker, verifier } = env;

    const now = Math.floor(Date.now() / 1000);
    const forgedPayload = {
      iss: worker.did,
      sub: subWorker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
        credentialSubject: {
          id: subWorker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: worker.did,
          grantedTo: subWorker.did,
          delegated: false,
        },
      },
    };
    const forgedCred = await createJwt(forgedPayload, worker.privateKey);

    const result = await verifier.verify(forgedCred, {
      expectedSubject: subWorker.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/must include a non-empty delegationChain/i);
  });

  it('issueDelegatedCredential throws when source carries a JSON-LD namespaced DelegatedAgentScopeCredential URI', async () => {
    const { human, supervisor, worker, subWorker } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const now = Math.floor(Date.now() / 1000);
    const namespacedWorkerPayload = {
      iss: supervisor.did,
      sub: worker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://abaxx.tech/vocab/v1',
        ],
        type: [
          'VerifiableCredential',
          'https://abaxx.tech/vocab#DelegatedAgentScopeCredential',
        ],
        credentialSubject: {
          id: worker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: supervisor.did,
          grantedTo: worker.did,
          delegatedGrantId: decodeJwt(rootCred).payload.jti!,
          delegated: false,
        },
      },
    };
    const workerCredNamespaced = await createJwt(namespacedWorkerPayload, supervisor.privateKey);

    await expect(
      issueDelegatedCredential(
        worker.did,
        createSigner(worker.privateKey),
        workerCredNamespaced,
        decodeJwt(workerCredNamespaced).payload.jti!,
        { columns: ['patients.name'], actions: ['read'] },
        {
          targetAgent: subWorker.did,
          columns: ['patients.name'],
          actions: ['read'],
          expiresIn: '1h',
        },
      ),
    ).rejects.toThrow(/re-delegation is not permitted/i);
  });

  it('verifier rejects a delegationChain ancestor declared with a JSON-LD namespaced DelegatedAgentScopeCredential URI', async () => {
    const { human, supervisor, worker, subWorker, verifier } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });

    // Hand-crafted: a non-conforming issuer could mint this directly, bypassing the issuance guard.
    const now = Math.floor(Date.now() / 1000);
    const namespacedAncestorPayload = {
      iss: supervisor.did,
      sub: worker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://abaxx.tech/vocab/v1',
        ],
        type: [
          'VerifiableCredential',
          'https://abaxx.tech/vocab#DelegatedAgentScopeCredential',
        ],
        credentialSubject: {
          id: worker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: supervisor.did,
          grantedTo: worker.did,
          delegatedGrantId: decodeJwt(rootCred).payload.jti!,
          delegated: false,
        },
      },
    };
    const namespacedAncestor = await createJwt(namespacedAncestorPayload, supervisor.privateKey);

    const reDelegatedPayload = {
      iss: worker.did,
      sub: subWorker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [namespacedAncestor],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
        credentialSubject: {
          id: subWorker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
          grantedBy: worker.did,
          grantedTo: subWorker.did,
          delegatedGrantId: decodeJwt(namespacedAncestor).payload.jti!,
          delegated: false,
        },
      },
    };
    const reDelegatedCred = await createJwt(reDelegatedPayload, worker.privateKey);

    const result = await verifier.verify(reDelegatedCred, {
      expectedSubject: subWorker.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/re-delegated/i);
  });

  it('verifier rejects a credential carrying a delegationChain without declaring DelegatedAgentScopeCredential type', async () => {
    const { human, supervisor, worker, subWorker, verifier } = env;

    const rootCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const now = Math.floor(Date.now() / 1000);
    const forgedPayload = {
      iss: worker.did,
      sub: subWorker.did,
      jti: randomUUID(),
      iat: now,
      exp: now + 3600,
      delegationChain: [rootCred],
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'AgentScopeCredential'],
        credentialSubject: {
          id: subWorker.did,
          scope: { columns: ['patients.name'], actions: ['read'] },
        },
      },
    };
    const forgedCred = await createJwt(forgedPayload, worker.privateKey);

    const result = await verifier.verify(forgedCred, {
      expectedSubject: subWorker.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toMatch(/must declare type DelegatedAgentScopeCredential/i);
  });
});
