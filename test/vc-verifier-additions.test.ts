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
import { VcVerifier, createJwt } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { generateDidKey } from '../src/auth/index.js';

describe('VC Verifier — T10 audience binding additions', () => {
  let verifier: VcVerifier;
  let issuer: ReturnType<typeof generateDidKey>;
  let agentA: ReturnType<typeof generateDidKey>;
  let agentB: ReturnType<typeof generateDidKey>;

  beforeEach(() => {
    verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
    issuer = generateDidKey();
    agentA = generateDidKey();
    agentB = generateDidKey();
    verifier.registerKey(issuer.did, issuer.publicKey);
    verifier.registerKey(agentA.did, agentA.publicKey);
    verifier.registerKey(agentB.did, agentB.publicKey);
  });

  // ─── Backward compatibility ────────────────────────────────────

  describe('backward compatibility (no options)', () => {
    it('existing scope-bearing VC still verifies without options', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            credentialSubject: {
              scope: { columns: ['table.col'], actions: ['read'] },
            },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
    });

    it('scope check still rejects VC missing scope when no options passed', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: { credentialSubject: {} },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
    });
  });

  // ─── skipScopeCheck (Decision #15) ───────────────────────────────

  describe('skipScopeCheck — for IdentityBindingCredentials', () => {
    it('binding VC without scope passes when skipScopeCheck: true', async () => {
      const now = Math.floor(Date.now() / 1000);
      // IdentityBindingCredential has no scope.columns by design
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            type: ['VerifiableCredential', 'IdentityBindingCredential'],
            credentialSubject: {
              humanDid: 'did:key:zABC',
              agentDid: agentA.did,
            },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt, { skipScopeCheck: true });
      expect(result.valid).toBe(true);
      expect(result.status).toBe('VALID');
    });

    it('binding VC without scope still fails WITHOUT skipScopeCheck', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            type: ['VerifiableCredential', 'IdentityBindingCredential'],
            credentialSubject: {
              humanDid: 'did:key:zABC',
              agentDid: agentA.did,
            },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(false);
      expect(result.status).toBe('MALFORMED');
    });

    it('skipScopeCheck does not affect other validity checks', async () => {
      // Expired binding VC should still be rejected even with skipScopeCheck
      const past = Math.floor(Date.now() / 1000) - 7200;
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: past,
          exp: past + 3600, // expired 1h ago
          vc: {
            type: ['VerifiableCredential', 'IdentityBindingCredential'],
            credentialSubject: { humanDid: 'did:key:zABC', agentDid: agentA.did },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt, { skipScopeCheck: true });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('EXPIRED');
    });
  });

  // ─── expectedSubject (Decision #16) ──────────────────────────────

  describe('expectedSubject — confused-deputy prevention', () => {
    it('passes when sub matches expectedSubject', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            credentialSubject: {
              scope: { columns: ['table.col'], actions: ['read'] },
            },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt, { expectedSubject: agentA.did });
      expect(result.valid).toBe(true);
    });

    it('rejects when sub does NOT match expectedSubject (confused-deputy)', async () => {
      const now = Math.floor(Date.now() / 1000);
      // VC was issued for agentA — agentB should NOT be able to use it
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            credentialSubject: {
              scope: { columns: ['table.col'], actions: ['read'] },
            },
          },
        },
        issuer.privateKey,
      );

      // agentB presents agentA's credential
      const result = await verifier.verify(jwt, { expectedSubject: agentB.did });
      expect(result.valid).toBe(false);
      // WRONG_SUBJECT not INVALID_SIGNATURE — sig is valid, wrong agent presented it
      expect(result.status).toBe('WRONG_SUBJECT');
      expect(result.error).toContain('subject mismatch');
    });

    it('subject check fires after signature check (signature still required)', async () => {
      // Tampered JWT — wrong signature — should fail on sig, not subject
      const now = Math.floor(Date.now() / 1000);
      const validJwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            credentialSubject: {
              scope: { columns: ['table.col'], actions: ['read'] },
            },
          },
        },
        issuer.privateKey,
      );

      // Tamper with the payload by substituting a different subject in the raw JWT
      const parts = validJwt.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      payload.sub = agentB.did; // change subject but keep original signature
      parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const tamperedJwt = parts.join('.');

      const result = await verifier.verify(tamperedJwt, { expectedSubject: agentB.did });
      expect(result.valid).toBe(false);
      // Should fail on signature, not subject (sig check comes first)
      expect(result.status).toBe('INVALID_SIGNATURE');
    });

    it('no subject check when expectedSubject not passed (legacy callers)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            credentialSubject: {
              scope: { columns: ['table.col'], actions: ['read'] },
            },
          },
        },
        issuer.privateKey,
      );

      // No expectedSubject — should pass (legacy behavior preserved)
      const result = await verifier.verify(jwt);
      expect(result.valid).toBe(true);
    });
  });

  // ─── Combined options ─────────────────────────────────────────────

  describe('skipScopeCheck + expectedSubject together', () => {
    it('binding VC passes with correct subject and skipScopeCheck', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            type: ['VerifiableCredential', 'IdentityBindingCredential'],
            credentialSubject: {
              humanDid: 'did:key:zABC',
              agentDid: agentA.did,
            },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt, {
        skipScopeCheck: true,
        expectedSubject: agentA.did,
      });
      expect(result.valid).toBe(true);
    });

    it('binding VC fails with wrong subject even with skipScopeCheck', async () => {
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createJwt(
        {
          iss: issuer.did,
          sub: agentA.did,
          iat: now,
          exp: now + 3600,
          vc: {
            type: ['VerifiableCredential', 'IdentityBindingCredential'],
            credentialSubject: { humanDid: 'did:key:zABC', agentDid: agentA.did },
          },
        },
        issuer.privateKey,
      );

      const result = await verifier.verify(jwt, {
        skipScopeCheck: true,
        expectedSubject: agentB.did, // wrong agent
      });
      expect(result.valid).toBe(false);
      expect(result.status).toBe('WRONG_SUBJECT');
    });
  });
});
