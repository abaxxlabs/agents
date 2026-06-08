import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { decodeJwt } from '#crypto/jwt.js';
import {
  generateDidKey,
  issueCredential,
  issueDelegatedCredential,
  createSigner,
} from '#auth/index.js';

function setup() {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();
  const subWorker = generateDidKey();

  const store = new InMemoryRevocationStore();
  const verifier = new VcVerifier({ revocationStore: store });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(supervisor.did, supervisor.publicKey);
  verifier.registerKey(worker.did, worker.publicKey);
  verifier.registerKey(subWorker.did, subWorker.publicKey);

  return { human, supervisor, worker, subWorker, store, verifier };
}

describe('Delegation chain revocation', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it('worker credential verifies as VALID before parent is revoked', async () => {
    const { human, supervisor, worker, verifier } = env;

    const parentCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      decodeJwt(parentCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    const result = await verifier.verify(workerCred, { expectedSubject: worker.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });

  it('revoking the parent credential invalidates the worker credential', async () => {
    const { human, supervisor, worker, store, verifier } = env;

    const parentCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const parentJti = decodeJwt(parentCred).payload.jti!;
    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      parentJti,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    await store.revoke(parentJti, { reason: 'parent compromised' });

    const result = await verifier.verify(workerCred, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('REVOKED');
    expect(result.error).toContain(parentJti);
  });

  it('revoking an unrelated credential does not invalidate the worker', async () => {
    const { human, supervisor, worker, store, verifier } = env;

    const parentCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      decodeJwt(parentCred).payload.jti!,
      { columns: ['patients.name'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    await store.revoke('some-other-unrelated-jti', {});

    const result = await verifier.verify(workerCred, { expectedSubject: worker.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });

  it('store error during chain check propagates as a thrown error (fail-closed)', async () => {
    const { human, supervisor, worker, store, verifier } = env;

    const parentCred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const parentJti = decodeJwt(parentCred).payload.jti!;
    const workerCred = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      parentJti,
      { columns: ['patients.name'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    const original = store.isRevoked.bind(store);
    let calls = 0;
    store.isRevoked = async (jti: string) => {
      calls++;
      if (jti === parentJti) throw new Error('store offline');
      return original(jti);
    };

    await expect(
      verifier.verify(workerCred, { expectedSubject: worker.did }),
    ).rejects.toThrow('store offline');
    expect(calls).toBeGreaterThan(0);
  });
});
