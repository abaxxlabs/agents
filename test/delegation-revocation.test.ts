// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { decodeJwt } from '../src/jwt-utils.js';
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

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = issueDelegatedCredential(
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

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const parentJti = decodeJwt(parentCred).payload.jti!;
    const workerCred = issueDelegatedCredential(
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

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = issueDelegatedCredential(
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

  it('multi-level chain: revoking the root invalidates a sub-worker', async () => {
    const { human, supervisor, worker, subWorker, store, verifier } = env;

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name', 'patients.dob'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const parentJti = decodeJwt(parentCred).payload.jti!;

    const workerCred = issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      parentCred,
      parentJti,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: worker.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '1h',
      },
    );

    const subWorkerCred = issueDelegatedCredential(
      worker.did,
      createSigner(worker.privateKey),
      workerCred,
      decodeJwt(workerCred).payload.jti!,
      { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
      {
        targetAgent: subWorker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '30m',
        operatorMaxDepth: 3,
      },
    );

    const beforeRevoke = await verifier.verify(subWorkerCred, {
      expectedSubject: subWorker.did,
    });
    expect(beforeRevoke.valid).toBe(true);

    await store.revoke(parentJti, { reason: 'root compromised' });

    const afterRevoke = await verifier.verify(subWorkerCred, {
      expectedSubject: subWorker.did,
    });
    expect(afterRevoke.valid).toBe(false);
    expect(afterRevoke.status).toBe('REVOKED');
    expect(afterRevoke.error).toContain(parentJti);
  });

  it('multi-level chain: revoking the intermediate worker invalidates the sub-worker', async () => {
    const { human, supervisor, worker, subWorker, store, verifier } = env;

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const workerCred = issueDelegatedCredential(
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
    const workerJti = decodeJwt(workerCred).payload.jti!;

    const subWorkerCred = issueDelegatedCredential(
      worker.did,
      createSigner(worker.privateKey),
      workerCred,
      workerJti,
      { columns: ['patients.name'], actions: ['read'] },
      {
        targetAgent: subWorker.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '30m',
        operatorMaxDepth: 3,
      },
    );

    await store.revoke(workerJti, { reason: 'intermediate compromised' });

    const result = await verifier.verify(subWorkerCred, { expectedSubject: subWorker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('REVOKED');
    expect(result.error).toContain(workerJti);
  });

  it('store error during chain check propagates as a thrown error (fail-closed)', async () => {
    const { human, supervisor, worker, store, verifier } = env;

    const parentCred = issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    const parentJti = decodeJwt(parentCred).payload.jti!;
    const workerCred = issueDelegatedCredential(
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
