import { describe, it, expect } from 'vitest';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { JsonFileBackend } from '#identity/keystore.js';
import { initializeServerIdentity } from '#identity/server-identity.js';
import {
  createBindingCredential,
  refreshBindingCredential,
  shouldRefresh,
  isExpired,
  parseBindingCredential,
} from '#identity/binding.js';
import type { OidcIdentity } from '#auth/provider.js';

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

describe('createBindingCredential()', () => {
  it('extracts orgDomain from tid (Azure AD)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const azureClaims = makeOidcIdentity({
      email: 'alice@company.com',
      claims: { tid: 'azure-guid-999' },
    });
    const binding = await createBindingCredential(server, 'did:key:z6Mk', azureClaims);
    expect(binding.orgDomain).toBe('azure-guid-999');
  });
});

describe('refreshBindingCredential()', () => {
  it('produces a new jti', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const claims = makeOidcIdentity();
    const original = await createBindingCredential(server, 'did:key:z6MkUser', claims);
    await new Promise((r) => setTimeout(r, 10));
    const refreshed = await refreshBindingCredential(server, original, claims);

    expect(refreshed.jti).not.toBe(original.jti);
    expect(refreshed.userDid).toBe(original.userDid);
  });
});

describe('shouldRefresh()', () => {
  it('returns true at exactly 80% elapsed', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = await createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(shouldRefresh(binding, binding.iat + 800)).toBe(true);
  });
});

describe('isExpired()', () => {
  it('returns false within overlap window (1 second after exp)', async () => {
    const keystore = makeTempKeystore();
    const server = await initializeServerIdentity(keystore);
    const binding = await createBindingCredential(server, 'did:key:z6Mk', makeOidcIdentity(), {
      membershipTtlSeconds: 1000,
    });
    expect(isExpired(binding, binding.exp + 1)).toBe(false);
  });
});

describe('parseBindingCredential()', () => {
  it('returns null for a malformed JWT', () => {
    expect(parseBindingCredential('not.a.valid.jwt.at.all')).toBeNull();
    expect(parseBindingCredential('')).toBeNull();
    expect(parseBindingCredential('only-one-part')).toBeNull();
  });
});
