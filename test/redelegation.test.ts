import { randomUUID } from 'node:crypto';
import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { decodeJwt, createJwt } from '#crypto/jwt.js';
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

    // Bypass the issuance guard to test rejection by the verifier independently.
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
});
