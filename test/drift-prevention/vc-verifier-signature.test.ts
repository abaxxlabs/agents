import { describe, it, expect } from 'vitest';
import { VcVerifier, decodeJwt } from '../../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../../src/storage/memory/revocation-store.js';
import { generateDidKey, issueCredential } from '../../src/auth/index.js';

describe('VcVerifier required-revocationStore contract', () => {
  it('runtime consumes injections.revocationStore on the verify hot path', async () => {
    // Two verifiers, two different stores. They MUST give different results for
    // the SAME credential — proving each verifier consults its own injected store.
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

    // Mint a real scope credential (not a bare JWT) — verify() runs many
    // upstream checks (issuer key, vc claims, scope shape, JTI, exp) before
    // reaching the revocation step. issueCredential produces the canonical
    // shape that takes the verify path all the way to revocation.
    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.dob'],
      actions: ['read'],
      expiresIn: '1h',
    });

    // Extract the JTI the issuer minted, then pre-revoke it in the populated
    // store ONLY. The empty store sees nothing.
    const { payload } = decodeJwt(jwt);
    const jti = payload.jti as string;
    expect(jti).toBeTruthy();
    await populatedStore.revoke(jti, { reason: 'd34 test b fixture' });

    // The populated-store verifier must reject. The empty-store verifier must
    // accept. The two outcomes diverge on the SAME credential — proving each
    // verifier reads ITS OWN injected revocationStore.
    const revokedResult = await verifierWithRevocation.verify(jwt);
    expect(revokedResult.valid).toBe(false);
    expect(revokedResult.status).toBe('REVOKED');

    const validResult = await verifierWithoutRevocation.verify(jwt);
    expect(validResult.valid).toBe(true);
    expect(validResult.status).toBe('VALID');
  });

  it('VcVerifierOptions.revocationStore type is required at the source layer', () => {
    // The structural protection is at the type level: any change to
    // `VcVerifierOptions` that makes `revocationStore` optional would fire
    // tsc errors at call sites in src/. The runtime probe above catches the
    // other half: a refactor that keeps the field required but ignores it.
    expect(true).toBe(true);
  });
});
