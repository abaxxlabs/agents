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
import { VcVerifier, createJwt, decodeJwt } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { generateDidKey, issueCredential, createSigner } from '../src/auth/index.js';
import { createPresentation, VP_TYPE } from '../src/identity/presentation.js';

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

  // Helper: issue a standard VC
  function issueTestVC() {
    return issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
  }

  // ─── VP Signature Verification ──────────────────────────────────

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
      // Tamper with the signature portion
      const parts = vp.split('.');
      parts[2] = parts[2].split('').reverse().join('');
      const tampered = parts.join('.');

      const result = await verifier.verify(tampered);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('INVALID_SIGNATURE');
    });

    it('rejects a VP from an unknown issuer (falls through to inner VC subject mismatch)', async () => {
      const unknownAgent = generateDidKey();
      const unknownSigner = createSigner(unknownAgent.privateKey);
      const vc = await issueTestVC();
      // VP signed by an agent whose key is NOT registered.
      // The VcVerifier resolves via did:key self-describing key, so the VP
      // signature check passes. But the inner VC subject (agent.did) won't
      // match the VP issuer (unknownAgent.did), producing WRONG_SUBJECT.
      const vp = await createPresentation(vc, unknownAgent.did, unknownSigner);

      const result = await verifier.verify(vp);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_SUBJECT');
    });

    it('rejects a VP with missing issuer (iss) claim', async () => {
      const now = Math.floor(Date.now() / 1000);
      // Manually create a VP JWT without an iss claim
      const vpPayload = {
        jti: 'test-nonce',
        iat: now,
        exp: now + 300,
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: [VP_TYPE],
          verifiableCredential: [await issueTestVC()],
        },
      };
      const vpJwt = await createJwt(vpPayload, agent.privateKey);

      const result = await verifier.verify(vpJwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('VP missing issuer');
    });
  });

  // ─── VP Audience Binding ────────────────────────────────────────

  describe('VP audience binding', () => {
    it('passes when VP audience matches expectedAudience', async () => {
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { audience: server.did });
      const result = await verifier.verify(vp, { expectedAudience: server.did });
      expect(result.valid).toBe(true);
    });

    it('rejects when VP audience does not match expectedAudience', async () => {
      const otherServer = generateDidKey();
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { audience: otherServer.did });

      const result = await verifier.verify(vp, { expectedAudience: server.did });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_AUDIENCE');
      expect(result.error).toContain('audience mismatch');
    });

    it('passes when no expectedAudience is specified (legacy callers)', async () => {
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer, { audience: server.did });
      // No expectedAudience — should still validate
      const result = await verifier.verify(vp);
      expect(result.valid).toBe(true);
    });

    it('rejects when VP has no audience and expectedAudience is set', async () => {
      // Fail-closed: VP without aud claim is rejected when expectedAudience is set.
      // Prevents cross-server replay of VPs that omit audience binding.
      const vc = await issueTestVC();
      const vp = await createPresentation(vc, agent.did, signer); // no audience
      const result = await verifier.verify(vp, { expectedAudience: server.did });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_AUDIENCE');
      expect(result.error).toContain('missing audience claim');
    });

    it('accepts audience as string[] and verifies against any listed DID', async () => {
      const serverA = generateDidKey();
      const serverB = generateDidKey();
      const serverC = generateDidKey();
      const vc = await issueTestVC();

      const vp = await createPresentation(vc, agent.did, signer, {
        audience: [serverA.did, serverB.did],
      });

      // Use separate verifier instances per audience check — each has its own JTI cache
      // so the same VP can be replayed by different parties (which is the multi-audience point).
      const mkVerifier = () =>
        new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
      const resultA = await mkVerifier().verify(vp, { expectedAudience: serverA.did });
      expect(resultA.valid).toBe(true);

      const resultB = await mkVerifier().verify(vp, { expectedAudience: serverB.did });
      expect(resultB.valid).toBe(true);

      const resultC = await mkVerifier().verify(vp, { expectedAudience: serverC.did });
      expect(resultC.valid).toBe(false);
      expect(resultC.status).toBe('WRONG_AUDIENCE');
      expect(resultC.error).toContain('audience mismatch');
    });
  });

  // ─── VP Expiry ──────────────────────────────────────────────────

  describe('VP expiry', () => {
    it('rejects an expired VP', async () => {
      const vc = await issueTestVC();
      const now = Math.floor(Date.now() / 1000);
      // Create a VP that expired 10 minutes ago
      const expiredPayload = {
        iss: agent.did,
        jti: 'expired-nonce',
        iat: now - 600,
        exp: now - 300,
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: [VP_TYPE],
          verifiableCredential: [vc],
        },
      };
      const expiredVp = await createJwt(expiredPayload, agent.privateKey);

      // Use strict verifier
      const strictVerifier = new VcVerifier({
        clockSkew: '1s',
        revocationStore: new InMemoryRevocationStore(),
      });
      strictVerifier.registerKey(human.did, human.publicKey);
      strictVerifier.registerKey(agent.did, agent.publicKey);

      const result = await strictVerifier.verify(expiredVp);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('EXPIRED');
      expect(result.error).toContain('VP expired');
    });
  });

  // ─── VP Replay Protection ──────────────────────────────────────

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

    it('accepts different VPs wrapping the same VC (different nonces)', async () => {
      const vc = await issueTestVC();
      const vp1 = await createPresentation(vc, agent.did, signer, { nonce: 'nonce-1' });
      const vp2 = await createPresentation(vc, agent.did, signer, { nonce: 'nonce-2' });

      const result1 = await verifier.verify(vp1);
      expect(result1.valid).toBe(true);

      const result2 = await verifier.verify(vp2);
      expect(result2.valid).toBe(true);
    });
  });

  // ─── VP Malformed Cases ─────────────────────────────────────────

  describe('VP malformed cases', () => {
    it('rejects a VP with no inner verifiable credentials', async () => {
      const now = Math.floor(Date.now() / 1000);
      const emptyVp = await createJwt(
        {
          iss: agent.did,
          jti: 'empty-vp-nonce',
          iat: now,
          exp: now + 300,
          vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: [VP_TYPE],
            verifiableCredential: [],
          },
        },
        agent.privateKey,
      );

      const result = await verifier.verify(emptyVp);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('no verifiable credentials');
    });

    it('rejects a VP with missing verifiableCredential array', async () => {
      const now = Math.floor(Date.now() / 1000);
      const noVcVp = await createJwt(
        {
          iss: agent.did,
          jti: 'no-vc-nonce',
          iat: now,
          exp: now + 300,
          vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: [VP_TYPE],
            // no verifiableCredential field
          },
        },
        agent.privateKey,
      );

      const result = await verifier.verify(noVcVp);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
      expect(result.error).toContain('no verifiable credentials');
    });
  });

  // ─── VP -> Inner VC Subject Binding ──────────────────────────────

  describe('VP -> inner VC subject binding', () => {
    it('rejects when VP issuer does not match inner VC subject', async () => {
      // Agent B creates a VP wrapping a VC issued to Agent A
      const agentB = generateDidKey();
      const signerB = createSigner(agentB.privateKey);
      verifier.registerKey(agentB.did, agentB.publicKey);

      const vcForAgentA = await issueTestVC(); // VC with sub = agent.did
      const vpByAgentB = await createPresentation(vcForAgentA, agentB.did, signerB);

      const result = await verifier.verify(vpByAgentB);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_SUBJECT');
      expect(result.error).toContain('subject mismatch');
    });

    it('accepts when VP issuer matches inner VC subject', async () => {
      const vc = await issueTestVC(); // VC with sub = agent.did
      const vp = await createPresentation(vc, agent.did, signer); // VP iss = agent.did

      const result = await verifier.verify(vp);
      expect(result.valid).toBe(true);
    });
  });
});

// ─── createPresentation() Unit Tests ─────────────────────────────

describe('createPresentation()', () => {
  let agent: ReturnType<typeof generateDidKey>;
  let human: ReturnType<typeof generateDidKey>;
  let signer: ReturnType<typeof createSigner>;

  beforeEach(() => {
    agent = generateDidKey();
    human = generateDidKey();
    signer = createSigner(agent.privateKey);
  });

  it('creates a valid JWT with VP structure', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const vp = await createPresentation(vc, agent.did, signer);
    expect(vp.split('.').length).toBe(3);

    const decoded = decodeJwt(vp);
    expect(decoded.payload.iss).toBe(agent.did);
    expect(decoded.payload.vp.type).toContain(VP_TYPE);
    expect(decoded.payload.vp.verifiableCredential).toHaveLength(1);
    expect(decoded.payload.vp.verifiableCredential[0]).toBe(vc);
  });

  it('sets audience claim when audience option is provided', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const server = generateDidKey();
    const vp = await createPresentation(vc, agent.did, signer, { audience: server.did });
    const decoded = decodeJwt(vp);
    expect(decoded.payload.aud).toBe(server.did);
  });

  it('does not set audience claim when audience is not provided', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const vp = await createPresentation(vc, agent.did, signer);
    const decoded = decodeJwt(vp);
    expect(decoded.payload.aud).toBeUndefined();
  });

  it('uses custom nonce when provided', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const vp = await createPresentation(vc, agent.did, signer, { nonce: 'my-custom-nonce' });
    const decoded = decodeJwt(vp);
    expect(decoded.payload.jti).toBe('my-custom-nonce');
  });

  it('generates a fresh nonce (UUID) when nonce is not provided', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const vp1 = await createPresentation(vc, agent.did, signer);
    const vp2 = await createPresentation(vc, agent.did, signer);
    const decoded1 = decodeJwt(vp1);
    const decoded2 = decodeJwt(vp2);
    expect(decoded1.payload.jti).not.toBe(decoded2.payload.jti);
  });

  it('sets exp to 60 seconds from now by default', async () => {
    // VP lifetime defaults to 60s. The VP lifetime IS the first-mover replay
    // window for a captured presentation; 60s is generous for an RPC round-trip.
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const before = Math.floor(Date.now() / 1000);
    const vp = await createPresentation(vc, agent.did, signer);
    const after = Math.floor(Date.now() / 1000);

    const decoded = decodeJwt(vp);
    expect(decoded.payload.exp).toBeGreaterThanOrEqual(before + 60);
    expect(decoded.payload.exp).toBeLessThanOrEqual(after + 60);
  });

  it('respects an explicit lifetime option', async () => {
    // Consumers needing a longer window (human-in-the-loop, resumable flows)
    // pass `lifetime: '5m'` — the prior default is opt-in, not removed.
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const before = Math.floor(Date.now() / 1000);
    const vp = await createPresentation(vc, agent.did, signer, { lifetime: '5m' });
    const after = Math.floor(Date.now() / 1000);

    const decoded = decodeJwt(vp);
    expect(decoded.payload.exp).toBeGreaterThanOrEqual(before + 300);
    expect(decoded.payload.exp).toBeLessThanOrEqual(after + 300);
  });

  it('accepts tight lifetimes (e.g. 10s) for high-frequency RPC', async () => {
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const before = Math.floor(Date.now() / 1000);
    const vp = await createPresentation(vc, agent.did, signer, { lifetime: '10s' });
    const after = Math.floor(Date.now() / 1000);

    const decoded = decodeJwt(vp);
    expect(decoded.payload.exp).toBeGreaterThanOrEqual(before + 10);
    expect(decoded.payload.exp).toBeLessThanOrEqual(after + 10);
  });

  it('throws on malformed lifetime string', async () => {
    // Surface misconfiguration at call time. A bad duration would otherwise
    // produce a VP with NaN exp that only fails downstream at verify().
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(createPresentation(vc, agent.did, signer, { lifetime: 'forever' })).rejects.toThrow(
      /Invalid duration format/,
    );
    await expect(createPresentation(vc, agent.did, signer, { lifetime: '30' })).rejects.toThrow(
      /Invalid duration format/,
    );
    await expect(createPresentation(vc, agent.did, signer, { lifetime: '' })).rejects.toThrow(
      /Invalid duration format/,
    );
  });

  it('throws on zero lifetime (born-expired VP footgun)', async () => {
    // parseDuration's regex `\d+` accepts '0s'/'0m' as syntactically valid
    // and returns 0 ms. Without a floor, this would produce exp = now:
    // immediately expired under tight clockSkew, or only clockSkew-valid under
    // default. Without the floor, a zero-lifetime VP would be born-expired.
    const vc = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['col.a'],
      actions: ['read'],
      expiresIn: '4h',
    });

    await expect(createPresentation(vc, agent.did, signer, { lifetime: '0s' })).rejects.toThrow(
      /at least 1 second/,
    );
    await expect(createPresentation(vc, agent.did, signer, { lifetime: '0m' })).rejects.toThrow(
      /at least 1 second/,
    );
    await expect(createPresentation(vc, agent.did, signer, { lifetime: '0h' })).rejects.toThrow(
      /at least 1 second/,
    );
    await expect(createPresentation(vc, agent.did, signer, { lifetime: '0d' })).rejects.toThrow(
      /at least 1 second/,
    );
  });
});
