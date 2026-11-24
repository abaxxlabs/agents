import { describe, it, expect } from 'vitest';
import { resolveScopeCeilingFromClaims } from '#auth/ceiling.js';

describe('resolveScopeCeilingFromClaims — provider dispatch', () => {
  it('routes AbaxxOne issuer (*.abaxx.tech) to abaxxone source', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://one.abaxx.tech/realms/main',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-abaxxone');
  });
});

describe('resolveScopeCeilingFromClaims — provider confusion prevention', () => {
  it('rejects attacker issuer with google as subdomain', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com.evil.com/',
        scope_columns: ['ticker'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });
});

describe('resolveScopeCeilingFromClaims — Google paths', () => {
  it('returns empty ceiling (fail-closed) for Google with no scope info', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
      },
    });
    expect(ceiling.source).toBe('oidc-google-directory');
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
    expect(ceiling.resolvedFrom).toEqual([]);
  });
});
