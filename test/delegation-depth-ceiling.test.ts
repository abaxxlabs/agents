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

type Key = ReturnType<typeof generateDidKey>;

function setup() {
  const human = generateDidKey();
  const supervisor = generateDidKey();
  const worker = generateDidKey();

  const store = new InMemoryRevocationStore();
  const verifier = new VcVerifier({ revocationStore: store });
  for (const k of [human, supervisor, worker]) verifier.registerKey(k.did, k.publicKey);

  return { human, supervisor, worker, store, verifier };
}

const futureExp = () => Math.floor(Date.now() / 1000) + 3600;

/** Forge a signed credential JWT with arbitrary depth/chain claims (bypasses issuance guards). */
function forge(
  issuer: Key,
  subject: string,
  opts: {
    delegated?: boolean;
    maxDepth?: number;
    delegationChain?: string[];
  } = {},
): Promise<string> {
  const type = opts.delegated
    ? ['VerifiableCredential', 'DelegatedAgentScopeCredential']
    : ['VerifiableCredential', 'AgentScopeCredential'];
  const payload: Record<string, unknown> = {
    iss: issuer.did,
    sub: subject,
    jti: `${subject}-${type[1]}`,
    iat: Math.floor(Date.now() / 1000),
    exp: futureExp(),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type,
      credentialSubject: { id: subject, scope: { columns: ['patients.name'], actions: ['read'] } },
    },
  };
  if (opts.maxDepth !== undefined) payload.maxDepth = opts.maxDepth;
  if (opts.delegationChain !== undefined) payload.delegationChain = opts.delegationChain;
  return createSigner(issuer.privateKey).signJwt(payload);
}

describe('Delegation depth ceiling enforcement', () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it('rejects a chain deeper than the embedded maxDepth ceiling with POLICY_VIOLATION', async () => {
    const { human, supervisor, worker, verifier } = env;

    // Forged chain: leaf -> mid -> root. `mid` is a plain (non-delegated) credential
    // carrying its own chain, so the re-delegation block does not catch the extra hop.
    const root = await forge(human, supervisor.did, { maxDepth: 2 });
    const mid = await forge(human, supervisor.did, { maxDepth: 2, delegationChain: [root] });
    const leaf = await forge(supervisor, worker.did, {
      delegated: true,
      maxDepth: 2,
      delegationChain: [mid],
    });

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('POLICY_VIOLATION');
  });

  it('rejects when an ancestor declares a tighter ceiling (minimum across the chain wins)', async () => {
    const { human, supervisor, worker, verifier } = env;

    // Leaf claims a generous ceiling, but an ancestor pins it to 1.
    const root = await forge(human, supervisor.did, { maxDepth: 1 });
    const leaf = await forge(supervisor, worker.did, {
      delegated: true,
      maxDepth: 5,
      delegationChain: [root],
    });

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('POLICY_VIOLATION');
  });

  it('enforces the library default when no maxDepth is embedded (pre-ceiling credentials)', async () => {
    const { human, supervisor, worker, verifier } = env;

    // No maxDepth anywhere -> default of 2 applies; a 2-deep chain still violates.
    const root = await forge(human, supervisor.did, {});
    const mid = await forge(human, supervisor.did, { delegationChain: [root] });
    const leaf = await forge(supervisor, worker.did, {
      delegated: true,
      delegationChain: [mid],
    });

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('POLICY_VIOLATION');
  });

  it('accepts a one-level delegated credential without an embedded ceiling (no regression)', async () => {
    const { human, supervisor, worker, verifier } = env;

    // Pre-ceiling shape: a single delegation hop, no maxDepth claim. Default 2 admits depth 1.
    const root = await forge(human, supervisor.did, {});
    const leaf = await forge(supervisor, worker.did, {
      delegated: true,
      delegationChain: [root],
    });

    const result = await verifier.verify(leaf, { expectedSubject: worker.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });

  it('accepts an honestly-issued delegated credential within its ceiling', async () => {
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
      { targetAgent: worker.did, columns: ['patients.name'], actions: ['read'], expiresIn: '1h' },
    );

    const result = await verifier.verify(workerCred, { expectedSubject: worker.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });

  it('leaves non-delegated credentials untouched', async () => {
    const { human, supervisor, verifier } = env;

    const cred = await issueCredential(human.did, human.privateKey, {
      agent: supervisor.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    const result = await verifier.verify(cred, { expectedSubject: supervisor.did });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });
});
