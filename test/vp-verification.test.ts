import { describe, it, expect, beforeEach } from 'vitest';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';
import { generateDidKey, issueCredential, createSigner } from '#auth/index.js';
import { createPresentation } from '#identity/presentation.js';

describe('VP Verification — VcVerifier', () => {
  let verifier: VcVerifier;
  let human: ReturnType<typeof generateDidKey>;
  let agent: ReturnType<typeof generateDidKey>;
  let server: ReturnType<typeof generateDidKey>;
  let signer: ReturnType<typeof createSigner>;

  beforeEach(() => {
    verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
    human = generateDidKey();
    agent = generateDidKey();
    server = generateDidKey();
    signer = createSigner(agent.privateKey);

    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
    verifier.registerKey(server.did, server.publicKey);
  });

  function issueTestVC() {
    return issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
  }

  describe('VP signature verification', () => {
    it('accepts a valid VP wrapping a valid VC', async () => {
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { audience: server.did });
      const result = await verifier.verify(vp, { expectedAudience: server.did });
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
    });

    it('rejects a VP with tampered signature', async () => {
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer);
      const parts = vp.split('.');
      parts[2] = parts[2].split('').reverse().join('');
      const tampered = parts.join('.');

      const result = await verifier.verify(tampered);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('INVALID_SIGNATURE');
    });
  });

  describe('VP audience binding', () => {
    it('rejects when VP audience does not match expectedAudience', async () => {
      const otherServer = generateDidKey();
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { audience: otherServer.did });

      const result = await verifier.verify(vp, { expectedAudience: server.did });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_AUDIENCE');
      expect(result.error).toContain('audience mismatch');
    });
  });

  describe('VP replay protection', () => {
    it('rejects a replayed VP (same nonce used twice)', async () => {
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { nonce: 'fixed-nonce' });

      const result1 = await verifier.verify(vp);
      expect(result1.valid).toBe(true);

      const result2 = await verifier.verify(vp);
      expect(result2.valid).toBe(false);
      expect(result2.status).toBe('REPLAYED');
      expect(result2.error).toContain('already been used');
    });
  });

  describe('VP -> inner VC subject binding', () => {
    it('rejects when VP issuer does not match inner VC subject', async () => {
      const agentB = generateDidKey();
      const signerB = createSigner(agentB.privateKey);
      verifier.registerKey(agentB.did, agentB.publicKey);

      const vcForAgentA = await issueTestVC();
      const vpByAgentB = await createPresentation(vcForAgentA, agentB.did, signerB);

      const result = await verifier.verify(vpByAgentB);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_SUBJECT');
      expect(result.error).toContain('subject mismatch');
    });
  });
});
