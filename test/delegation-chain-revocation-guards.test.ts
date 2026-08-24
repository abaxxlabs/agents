import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { checkDelegationChainRevocation } from '#identity/delegation-chain.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, createSigner } from '#auth/index.js';

function hashCredentialId(jwt: string): string {
  return createHash('sha256').update(jwt).digest('hex').slice(0, 16);
}

function makeDeps(knownKeys = new Map<string, Uint8Array>()) {
  return {
    revocationStore: new InMemoryRevocationStore(),
    knownKeys,
    emitRevocationTelemetry: () => {},
  };
}

/** Sign a minimal plain (non-delegated, no inner chain) credential that passes the walker. */
function signPlain(issuer: ReturnType<typeof generateDidKey>, jti: string): Promise<string> {
  return createSigner(issuer.privateKey).signJwt({
    iss: issuer.did,
    sub: issuer.did,
    jti,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'AgentScopeCredential'],
      credentialSubject: { id: issuer.did },
    },
  });
}

describe('checkDelegationChainRevocation guards', () => {
  it('rejects a chain whose entries are all non-strings as MALFORMED', async () => {
    const result = await checkDelegationChainRevocation([42, null, {}], makeDeps());
    expect(result?.valid).toBe(false);
    expect(result?.status).toBe('MALFORMED');
  });

  it('rejects ancestor revoked by hashed credential id', async () => {
    const issuer = generateDidKey();
    const knownKeys = new Map([[issuer.did, issuer.publicKey]]);
    const ancestor = await signPlain(issuer, 'ancestor-jti');

    const deps = makeDeps(knownKeys);
    await deps.revocationStore.revoke(hashCredentialId(ancestor), {});

    const result = await checkDelegationChainRevocation([ancestor], deps);
    expect(result?.valid).toBe(false);
    expect(result?.status).toBe('REVOKED');
  });

  it('rejects a wide flat chain exceeding the total-node cap before verifying every node', async () => {
    const issuer = generateDidKey();
    const knownKeys = new Map([[issuer.did, issuer.publicKey]]);
    const chain = await Promise.all(
      Array.from({ length: 11 }, (_, i) => signPlain(issuer, `node-${i}`)),
    );

    const deps = makeDeps(knownKeys);
    let lookups = 0;
    const original = deps.revocationStore.isRevoked.bind(deps.revocationStore);
    deps.revocationStore.isRevoked = async (jti: string) => {
      lookups++;
      return original(jti);
    };

    const result = await checkDelegationChainRevocation(chain, deps);
    expect(result?.valid).toBe(false);
    expect(result?.status).toBe('MALFORMED');
    // Each ancestor now checks up to 2 revocation identifiers (hash + jti).
    expect(lookups).toBeLessThanOrEqual(20);
  });
});
