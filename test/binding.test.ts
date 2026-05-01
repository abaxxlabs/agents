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

// Unit tests for IdentityBinding: credential creation, refresh, expiry, and parsing.

import { describe, it, expect } from 'vitest';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend } from '../src/identity/keystore.js';
import { initializeServerIdentity } from '../src/identity/server-identity.js';
import {
  createBindingCredential,
  refreshBindingCredential,
  shouldRefresh,
  isExpired,
  parseBindingCredential,
} from '../src/identity/binding.js';
import type { OidcIdentity } from '../src/auth/provider.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeTempKeystore(): JsonFileBackend {
  const dir = join(tmpdir(), `binding-test-${randomBytes(4).toString('hex')}`);
  mkdirSync(dir, { recursive: true });
  return new JsonFileBackend(join(dir, 'keystore.json'));
}

function makeOidcIdentity(overrides: Partial<OidcIdentity> = {}): OidcIdentity {
  return {
    humanDid: 'did:key:z6MkUserDid',
    sub: 'user-sub-1234',
    email: 'alice@company.com',
    issuer: 'https://accounts.google.com',
    claims: { hd: 'company.com', ...overrides.claims },
    ...overrides,
  };
}

// ─── createBindingCredential ──────────────────────────────────────────────────

describe('createBindingCredential()', () => {
  it('returns a valid IdentityBindingCredential structure', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const userDid = 'did:key:z6MkUser';
    const claims = makeOidcIdentity();

    const binding = createBindingCredential(server, userDid, claims);

    expect(binding.userDid).toBe(userDid);
    expect(binding.serverDid).toBe(server.did);
    expect(binding.oauthIssuer).toBe('https://accounts.google.com');
    expect(binding.oauthSubject).toBe('user-sub-1234');
    expect(binding.orgDomain).toBe('company.com'); // extracted from hd claim
    expect(typeof binding.jwt).toBe('string');
    expect(typeof binding.jti).toBe('string');
    expect(binding.exp).toBeGreaterThan(binding.iat);
  });

  it('JWT has 3 parts (header.payload.signature)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity());
    expect(binding.jwt.split('.')).toHaveLength(3);
  });

  it('JWT payload contains IdentityBindingCredential type', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity());

    const parts = binding.jwt.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    expect(payload.vc.type).toContain('IdentityBindingCredential');
    expect(payload.iss).toBe(server.did);
    expect(payload.sub).toBe('did:key:z6Mk');
  });

  it('defaults to 24h TTL', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity());
    const ttl = binding.exp - binding.iat;
    expect(ttl).toBe(24 * 60 * 60); // 86400 seconds
  });

  it('respects custom membershipTtlSeconds', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 3600, // 1 hour
    });
    expect(binding.exp - binding.iat).toBe(3600);
  });

  it('extracts null orgDomain for consumer email', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const consumerClaims = makeOidcIdentity({ email: 'alice@gmail.com', claims: {} });
    const binding = createBindingCredential(server, 'did:key:z6Mk', consumerClaims);
    expect(binding.orgDomain).toBeNull();
  });

  it('extracts orgDomain from tid (Azure AD)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const azureClaims = makeOidcIdentity({
      email: 'alice@company.com',
      claims: { tid: 'azure-guid-999' },
    });
    const binding = createBindingCredential(server, 'did:key:z6Mk', azureClaims);
    expect(binding.orgDomain).toBe('azure-guid-999');
  });

  describe('extraConsumerDomains plumbing', () => {
    it('honors extraConsumerDomains via BindingOptions — custom domain becomes consumer', async () => {
      const keystore = makeTempKeystore();
      const server = await initializeServerIdentity(keystore);
      const claims = makeOidcIdentity({ email: 'alice@contractor.com', claims: {} });
      // Without extraConsumerDomains: contractor.com falls through as enterprise.
      const defaultBinding = createBindingCredential(server, 'did:key:z6Mk', claims);
      expect(defaultBinding.orgDomain).toBe('contractor.com');
      // With extraConsumerDomains: contractor.com is excluded.
      const customBinding = createBindingCredential(server, 'did:key:z6Mk', claims, {
        extraConsumerDomains: ['contractor.com', 'freelance.io'],
      });
      expect(customBinding.orgDomain).toBeNull();
    });

    it('refreshBindingCredential propagates extraConsumerDomains', async () => {
      const keystore = makeTempKeystore();
      const server = await initializeServerIdentity(keystore);
      const claims = makeOidcIdentity({ email: 'alice@contractor.com', claims: {} });
      const original = createBindingCredential(server, 'did:key:z6Mk', claims, {
        extraConsumerDomains: ['contractor.com'],
      });
      expect(original.orgDomain).toBeNull();
      const refreshed = refreshBindingCredential(server, original, claims, {
        extraConsumerDomains: ['contractor.com'],
      });
      expect(refreshed.orgDomain).toBeNull();
    });
  });

  it('generates unique jti per credential', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const claims = makeOidcIdentity();
    const a = createBindingCredential(server, 'did:key:z6Mk', claims);
    const b = createBindingCredential(server, 'did:key:z6Mk', claims);
    expect(a.jti).not.toBe(b.jti);
  });
});

// ─── refreshBindingCredential ─────────────────────────────────────────────────

describe('refreshBindingCredential()', () => {
  it('produces a new jti', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const claims = makeOidcIdentity();
    const original = createBindingCredential(server, 'did:key:z6MkUser', claims);
    await new Promise((r) => setTimeout(r, 10));
    const refreshed = refreshBindingCredential(server, original, claims);

    expect(refreshed.jti).not.toBe(original.jti);
    expect(refreshed.userDid).toBe(original.userDid);
  });

  it('inherits TTL from original binding', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const claims = makeOidcIdentity();
    const original = createBindingCredential(server, 'did:key:z6Mk', claims, {
      membershipTtlSeconds: 7200, // 2 hours
    });

    const refreshed = refreshBindingCredential(server, original, claims);
    expect(refreshed.exp - refreshed.iat).toBe(7200);
  });

  it('allows TTL override on refresh', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const claims = makeOidcIdentity();
    const original = createBindingCredential(server, 'did:key:z6Mk', claims, {
      membershipTtlSeconds: 86400,
    });

    const refreshed = refreshBindingCredential(server, original, claims, {
      membershipTtlSeconds: 3600, // override to 1h
    });
    expect(refreshed.exp - refreshed.iat).toBe(3600);
  });
});

// ─── shouldRefresh ────────────────────────────────────────────────────────────

describe('shouldRefresh()', () => {
  it('returns false at 0% elapsed', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(shouldRefresh(binding, binding.iat)).toBe(false);
  });

  it('returns false at 79% elapsed', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(shouldRefresh(binding, binding.iat + 790)).toBe(false);
  });

  it('returns true at exactly 80% elapsed', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(shouldRefresh(binding, binding.iat + 800)).toBe(true);
  });

  it('returns true at 100% elapsed (past expiry)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(shouldRefresh(binding, binding.exp + 10)).toBe(true);
  });
});

// ─── isExpired ────────────────────────────────────────────────────────────────

describe('isExpired()', () => {
  it('returns false before exp', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(isExpired(binding, binding.iat + 500)).toBe(false);
  });

  it('returns false within overlap window (1 second after exp)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    // 1 second into the 300s overlap window
    expect(isExpired(binding, binding.exp + 1)).toBe(false);
  });

  it('returns false at edge of overlap window (300s after exp)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    // Right at 300s overlap boundary — still valid
    expect(isExpired(binding, binding.exp + 300)).toBe(false);
  });

  it('returns true after overlap window (301s after exp)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(isExpired(binding, binding.exp + 301)).toBe(true);
  });
});

// ─── parseBindingCredential ───────────────────────────────────────────────────

describe('parseBindingCredential()', () => {
  it('parses a valid binding JWT', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = createBindingCredential(server, 'did:key:z6MkUser', makeOidcIdentity());
    const parsed = parseBindingCredential(binding.jwt);
    expect(parsed).not.toBeNull();
    expect(parsed!.userDid).toBe('did:key:z6MkUser');
    expect(parsed!.serverDid).toBe(server.did);
    expect(parsed!.jti).toBe(binding.jti);
  });

  it('returns null for a non-binding JWT', async () => {
    const keystore = makeTempKeystore();
    await initializeServerIdentity(keystore);
    const { issueCredential } = await import('../src/auth/index.js');
    const { generateDidKey } = await import('../src/auth/index.js');
    const human = generateDidKey();
    const agent = generateDidKey();
    const scopeJwt = issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: ['table.col'],
      actions: ['read'],
      expiresIn: '1h',
    });
    const parsed = parseBindingCredential(scopeJwt);
    expect(parsed).toBeNull();
  });

  it('returns null for a malformed JWT', () => {
    expect(parseBindingCredential('not.a.valid.jwt.at.all')).toBeNull();
    expect(parseBindingCredential('')).toBeNull();
    expect(parseBindingCredential('only-one-part')).toBeNull();
  });
});
