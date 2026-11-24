import { describe, it, expect } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { decodeJwt } from '#crypto/jwt.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, issueCredential } from '#auth/index.js';

describe('VcVerifier required-revocationStore contract', () => {
  it('runtime consumes injections.revocationStore on the verify hot path', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();

    const populatedStore = new InMemoryRevocationStore();
    const emptyStore = new InMemoryRevocationStore();

    const verifierWithRevocation = new VcVerifier({
      clockSkew: '30s',
      revocationStore: populatedStore,
    });
    verifierWithRevocation.registerKey(human.did, human.publicKey);
    verifierWithRevocation.registerKey(agent.did, agent.publicKey);

    const verifierWithoutRevocation = new VcVerifier({
      clockSkew: '30s',
      revocationStore: emptyStore,
    });
    verifierWithoutRevocation.registerKey(human.did, human.publicKey);
    verifierWithoutRevocation.registerKey(agent.did, agent.publicKey);

    // Use a real issued credential so earlier verification checks cannot mask revocation behavior.
    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '1h',
    });

    const { payload } = decodeJwt(jwt);
    const jti = payload.jti as string;
    expect(jti).toBeTruthy();
    await populatedStore.revoke(jti, { reason: 'd34 test b fixture' });

    const revokedResult = await verifierWithRevocation.verify(jwt);
    expect(revokedResult.valid).toBe(false);
    expect(revokedResult.status).toBe('REVOKED');

    const validResult = await verifierWithoutRevocation.verify(jwt);
    expect(validResult.valid).toBe(true);
    expect(validResult.status).toBe('VALID');
  });
});
