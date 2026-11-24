import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, createSigner } from '#auth/index.js';

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

    // A non-delegated intermediate bypasses the re-delegation guard, isolating the depth check.
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
});
