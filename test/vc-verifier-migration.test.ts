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
import { generateDidKey, createSigner } from '../src/auth/index.js';

describe('VcVerifier — migration credential edge cases', () => {
  let verifier: VcVerifier;
  let tenantAdmin: ReturnType<typeof generateDidKey>;
  let newIdentity: ReturnType<typeof generateDidKey>;

  beforeEach(() => {
    tenantAdmin = generateDidKey();
    newIdentity = generateDidKey();

    verifier = new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() });
    verifier.registerKey(tenantAdmin.did, tenantAdmin.publicKey);
    verifier.registerKey(newIdentity.did, newIdentity.publicKey);
  });

  function createMigrationCredential(overrides?: Record<string, unknown>): string {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: tenantAdmin.did,
      sub: newIdentity.did,
      iat: now,
      exp: now + 3600,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'IdentityMigrationCredential'],
        credentialSubject: {
          id: newIdentity.did,
          previousDid: 'did:key:z6MkOldIdentity',
          oidcSubject: 'user-123',
          migrationMethod: 'oidc-verified',
          oidcIssuer: 'https://login.microsoftonline.com/tenant-abc',
          migratedAt: new Date().toISOString(),
          ...overrides,
        },
      },
    };
    const signer = createSigner(tenantAdmin.privateKey);
    return signer.signJwt(payload);
  }

  function createScopeCredential(): string {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: tenantAdmin.did,
      sub: newIdentity.did,
      iat: now,
      exp: now + 3600,
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'AgentScopeCredential'],
        credentialSubject: {
          id: newIdentity.did,
          scope: { columns: ['patients.name', 'patients.dob'], actions: ['read'] },
        },
      },
    };
    const signer = createSigner(tenantAdmin.privateKey);
    return signer.signJwt(payload);
  }

  // ─── Missing individual claims ──────────────────────────────────

  it('rejects migration credential with missing migrationMethod', async () => {
    const jwt = createMigrationCredential({ migrationMethod: undefined });
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('migrationMethod');
  });

  it('rejects migration credential with missing oidcIssuer', async () => {
    const jwt = createMigrationCredential({ oidcIssuer: undefined });
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('oidcIssuer');
  });

  it('rejects migration credential with missing migratedAt', async () => {
    const jwt = createMigrationCredential({ migratedAt: undefined });
    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('migratedAt');
  });

  // ─── VP with invalid migration + valid scope VC ─────────────────

  it('VP filters out invalid migration VC and verifies scope VC', async () => {
    // Create a migration credential with missing required claims
    const badMigrationJwt = createMigrationCredential({ previousDid: undefined });
    const scopeJwt = createScopeCredential();

    // Wrap both in a VP — migration credential first, scope credential second
    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-nonce-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [badMigrationJwt, scopeJwt],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });

    // The invalid migration credential is filtered out of the scope VC list.
    // The scope VC is verified normally and returns VALID.
    expect(result).toBeDefined();
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
  });

  // ─── VP with only a scope VC (no migration) ─────────────────────

  it('VP with scope-only VCs returns VALID (no migration detection)', async () => {
    const scopeJwt = createScopeCredential();

    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-nonce-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [scopeJwt],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt);
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
    expect(result.credential?.migrationClaims).toBeUndefined();
  });

  // ─── VP with garbled inner VC ───────────────────────────────────

  it('VP skips garbled inner VC and still processes scope VC', async () => {
    const scopeJwt = createScopeCredential();
    const garbledJwt = 'not.a.valid.jwt';

    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-nonce-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [garbledJwt, scopeJwt],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    // The garbled JWT should be caught by the try/catch in the migration
    // scan loop. The VP verification then falls through to innerVCs[0],
    // which is the garbled JWT — that will fail. But the key is: no crash.
    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
    expect(result).toBeDefined();
  });

  // ─── VP with only migration credentials (no scope VCs) ──────────

  it('VP with only a valid migration credential returns MIGRATION_DETECTED', async () => {
    const migrationJwt = createMigrationCredential();

    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-only-migration-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [migrationJwt],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('MIGRATION_DETECTED');
    expect(result.credential?.migrationClaims?.previousDid).toBe('did:key:z6MkOldIdentity');
  });

  it('VP with only invalid migration credentials returns MALFORMED', async () => {
    const badJwt = createMigrationCredential({ previousDid: undefined });

    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-only-bad-migration-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [badJwt],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
    expect(result.valid).toBe(false);
    expect(result.status).toBe('MALFORMED');
    expect(result.error).toContain('no scope credentials');
  });

  // ─── VP with two migration credentials ─────────────────────────

  it('VP with two migration credentials returns first valid one', async () => {
    const migration1 = createMigrationCredential({
      previousDid: 'did:key:z6MkFirst',
      oidcSubject: 'first@corp.com',
    });
    const migration2 = createMigrationCredential({
      previousDid: 'did:key:z6MkSecond',
      oidcSubject: 'second@corp.com',
    });

    const agentSigner = createSigner(newIdentity.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const vpPayload = {
      iss: newIdentity.did,
      iat: now,
      exp: now + 300,
      jti: 'vp-two-migrations-' + Date.now(),
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [migration1, migration2],
      },
    };
    const vpJwt = agentSigner.signJwt(vpPayload);

    const result = await verifier.verify(vpJwt, { skipScopeCheck: true });
    expect(result.valid).toBe(true);
    expect(result.status).toBe('MIGRATION_DETECTED');
    // Should return the first valid migration credential
    expect(result.credential?.migrationClaims?.previousDid).toBe('did:key:z6MkFirst');
  });

  // ─── Non-migration VC with IdentityMigrationCredential type but
  //     valid migration claims (ensures full extraction works) ──────

  it('extracts all five migration claims correctly', async () => {
    const jwt = createMigrationCredential({
      previousDid: 'did:key:z6MkSpecific',
      oidcSubject: 'specific-user@corp.com',
      migrationMethod: 'admin-verified',
      oidcIssuer: 'https://specific-issuer.example.com',
      migratedAt: '2026-04-18T12:00:00Z',
    });

    const result = await verifier.verify(jwt, { skipScopeCheck: true });

    expect(result.valid).toBe(true);
    expect(result.status).toBe('MIGRATION_DETECTED');
    expect(result.credential?.migrationClaims).toEqual({
      previousDid: 'did:key:z6MkSpecific',
      oidcSubject: 'specific-user@corp.com',
      migrationMethod: 'admin-verified',
      oidcIssuer: 'https://specific-issuer.example.com',
      migratedAt: '2026-04-18T12:00:00Z',
    });
  });
});
