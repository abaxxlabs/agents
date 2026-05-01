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
import {
  VcVerifier,
  createJwt,
  verifyJwtSignature,
  decodeJwt,
  resolveDidKey,
} from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { generateDidKey, issueCredential } from '../src/auth/index.js';

describe('VC Verifier', () => {
  let verifier: VcVerifier;
  let human: ReturnType<typeof generateDidKey>;
  let agent: ReturnType<typeof generateDidKey>;

  beforeEach(() => {
    verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
    human = generateDidKey();
    agent = generateDidKey();
    // Register both keys
    verifier.registerKey(human.did, human.publicKey);
    verifier.registerKey(agent.did, agent.publicKey);
  });

  describe('JWT creation and verification', () => {
    it('creates a valid JWT', () => {
      const jwt = createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
      expect(jwt.split('.').length).toBe(3);
    });

    it('verifies a valid JWT signature', () => {
      const jwt = createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
      expect(verifyJwtSignature(jwt, human.publicKey)).toBe(true);
    });

    it('rejects a JWT with wrong key', () => {
      const jwt = createJwt({ iss: human.did, sub: 'test' }, human.privateKey);
      const other = generateDidKey();
      expect(verifyJwtSignature(jwt, other.publicKey)).toBe(false);
    });

    it('decodes JWT payload', () => {
      const jwt = createJwt({ iss: human.did, sub: agent.did, custom: 'data' }, human.privateKey);
      const { payload } = decodeJwt(jwt);
      expect(payload.iss).toBe(human.did);
      expect(payload.sub).toBe(agent.did);
      expect(payload.custom).toBe('data');
    });
  });

  describe('did:key resolution', () => {
    it('resolves a did:key to Ed25519 public key', () => {
      const pk = resolveDidKey(human.did);
      expect(pk.length).toBe(32);
      expect(Buffer.from(pk).equals(Buffer.from(human.publicKey))).toBe(true);
    });

    it('rejects non-did:key DIDs', () => {
      expect(() => resolveDidKey('did:ion:abc123')).toThrow('Not a did:key');
    });
  });

  describe('credential verification', () => {
    function makeCredential(overrides: Record<string, unknown> = {}) {
      return issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
        ...overrides,
      });
    }

    it('verifies a valid credential', async () => {
      const jwt = makeCredential();
      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
      expect(result.credential?.issuer).toBe(human.did);
      expect(result.credential?.subject).toBe(agent.did);
      expect(result.credential?.scope.columns).toEqual(['patients.name', 'patients.dob']);
    });

    it('rejects expired credential', async () => {
      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1s',
      });

      // Wait for expiry (1s credential + margin)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Create a verifier with very small clock skew
      const strictVerifier = new VcVerifier({
        clockSkew: '0s',
        revocationStore: new InMemoryRevocationStore(),
      });
      strictVerifier.registerKey(human.did, human.publicKey);

      const result = await strictVerifier.verify(jwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('EXPIRED');
    });

    it('accepts credential within clock skew tolerance', async () => {
      // Create credential that expires "now" (0s) but verifier allows 30s skew
      const now = Math.floor(Date.now() / 1000);
      const jwt = createJwt(
        {
          iss: human.did,
          sub: agent.did,
          iat: now - 10,
          exp: now - 5, // expired 5 seconds ago
          vc: {
            credentialSubject: {
              id: agent.did,
              scope: { columns: ['patients.name'], actions: ['read'] },
            },
          },
        },
        human.privateKey,
      );

      // 30s clock skew should accept this
      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(true);
    });

    it('rejects credential with invalid signature', async () => {
      const jwt = makeCredential();
      // Tamper with the signature
      const parts = jwt.split('.');
      parts[2] = parts[2].slice(0, -5) + 'XXXXX';
      const tampered = parts.join('.');

      const result = await verifier.verify(tampered);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('INVALID_SIGNATURE');
    });

    it('rejects credential with missing scope claim', async () => {
      const jwt = createJwt(
        {
          iss: human.did,
          sub: agent.did,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          vc: {
            credentialSubject: {
              id: agent.did,
              // no scope!
            },
          },
        },
        human.privateKey,
      );

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
    });

    it('rejects credential from non-did:key issuer (unsupported method)', async () => {
      // did:key is self-resolving, so test with an unsupported DID method
      const fakeJwt = createJwt(
        {
          iss: 'did:ion:EiAunknown123',
          sub: agent.did,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          vc: {
            credentialSubject: {
              id: agent.did,
              scope: { columns: ['patients.name'], actions: ['read'] },
            },
          },
        },
        human.privateKey,
      ); // Sign with human key (sig won't match issuer, but we'll hit issuer resolution first)

      const freshVerifier = new VcVerifier({
        clockSkew: '30s',
        revocationStore: new InMemoryRevocationStore(),
      });
      const result = await freshVerifier.verify(fakeJwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('UNKNOWN_ISSUER');
    });
  });

  describe('DID cache', () => {
    it('caches resolved keys', async () => {
      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      });

      await verifier.verify(jwt);
      expect(verifier.cacheSize).toBeGreaterThan(0);
    });
  });

  describe('scope extraction', () => {
    it('extracts scope from valid credential', () => {
      const jwt = issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: ['patients.name', 'patients.dob'],
        actions: ['read'],
        expiresIn: '4h',
      });

      const scope = verifier.extractScope(jwt);
      expect(scope.columns).toEqual(['patients.name', 'patients.dob']);
      expect(scope.actions).toEqual(['read']);
    });
  });
});
