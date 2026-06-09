import { describe, it, expect } from 'vitest';
import { resolveScopeCeilingFromClaims } from '#auth/ceiling.js';

// ─── Provider Routing ─────────────────────────────────────────────

describe('resolveScopeCeilingFromClaims — provider dispatch', () => {
  it('routes Google issuer to google-directory source', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-google-directory');
  });

  it('routes Microsoft issuer (login.microsoftonline.com) to microsoft-roles source', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://login.microsoftonline.com/tenant-id/v2.0',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-microsoft-roles');
  });

  it('routes Microsoft issuer (sts.windows.net) to microsoft-roles source', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://sts.windows.net/tenant-id/',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-microsoft-roles');
  });

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

  it('routes AbaxxOne issuer (abaxxone.com) to abaxxone source', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://abaxxone.com/auth',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-abaxxone');
  });

  it('routes unknown issuer to Keycloak default (oidc-claims)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://keycloak.example.com/realms/demo',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });

  it('routes missing issuer to Keycloak default', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });
});

// ─── Provider Confusion Prevention ────────────────────────────────

describe('resolveScopeCeilingFromClaims — provider confusion prevention', () => {
  it('rejects attacker issuer containing "accounts.google.com" as substring', () => {
    // An attacker-controlled issuer like "https://evil.com/accounts.google.com/"
    // must NOT match the Google resolver.
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://evil.com/accounts.google.com/',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    // Should fall through to Keycloak default, NOT google-directory
    expect(ceiling.source).toBe('oidc-claims');
  });

  it('rejects attacker issuer with google as subdomain', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com.evil.com/',
        scope_columns: ['ticker'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });

  it('rejects attacker issuer containing "login.microsoftonline.com" as path', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://evil.com/login.microsoftonline.com/',
        scope_columns: ['ticker'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });

  it('rejects attacker issuer containing "abaxx.tech" as path', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://evil.com/one.abaxx.tech/',
        scope_columns: ['ticker'],
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
  });
});

// ─── Invalid Issuer Handling ──────────────────────────────────────

describe('resolveScopeCeilingFromClaims — invalid issuer URL', () => {
  it('falls through to Keycloak when iss is not a valid URL', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'not-a-url',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    // Invalid URL should fall through to Keycloak default
    expect(ceiling.source).toBe('oidc-claims');
    expect(ceiling.columns).toEqual(['ticker']);
  });

  it('falls through with empty ceiling when iss is invalid and no scope claims', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'not-a-url',
      },
    });
    expect(ceiling.source).toBe('oidc-claims');
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
  });
});

// ─── Google Ceiling Resolver ──────────────────────────────────────

describe('resolveScopeCeilingFromClaims — Google paths', () => {
  it('extracts scope from Google Workspace customSchemas.agent_id', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
        customSchemas: {
          agent_id: {
            scope_columns: ['ticker', 'side'],
            scope_actions: ['read'],
          },
        },
      },
    });
    expect(ceiling.source).toBe('oidc-google-directory');
    expect(ceiling.columns).toEqual(['ticker', 'side']);
    expect(ceiling.actions).toEqual(['read']);
    expect(ceiling.resolvedFrom).toEqual(['customSchemas.agent_id']);
  });

  it('accepts customSchemas.agentId (camelCase variant)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
        customSchemas: {
          agentId: {
            scope_columns: ['ticker'],
            scope_actions: ['read'],
          },
        },
      },
    });
    expect(ceiling.source).toBe('oidc-google-directory');
    expect(ceiling.columns).toEqual(['ticker']);
  });

  it('strips wildcards from Google customSchemas', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
        customSchemas: {
          agent_id: {
            scope_columns: ['*', 'ticker'],
            scope_actions: ['*', 'read'],
          },
        },
      },
    });
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.actions).toEqual(['read']);
  });

  it('falls back to scope_columns/scope_actions for Google with google-fallback', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://accounts.google.com',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-google-directory');
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.resolvedFrom).toContain('google-fallback');
  });

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

// ─── Microsoft Ceiling Resolver ───────────────────────────────────

describe('resolveScopeCeilingFromClaims — Microsoft paths', () => {
  it('extracts scope from optional claims (scope_columns/scope_actions)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://login.microsoftonline.com/tenant-id/v2.0',
        scope_columns: ['ticker', 'side'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-microsoft-roles');
    expect(ceiling.columns).toEqual(['ticker', 'side']);
    expect(ceiling.resolvedFrom).toContain('optional-claims');
  });

  it('extracts roles from Entra app roles claim', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://login.microsoftonline.com/tenant-id/v2.0',
        roles: ['DataReader', 'Analyst'],
      },
    });
    expect(ceiling.source).toBe('oidc-microsoft-roles');
    // Roles are stored in resolvedFrom, not mapped to columns (stub)
    expect(ceiling.resolvedFrom).toEqual(['role:DataReader', 'role:Analyst']);
    expect(ceiling.columns).toEqual([]);
  });

  it('returns empty ceiling (fail-closed) for Microsoft with no scope info', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://login.microsoftonline.com/tenant-id/v2.0',
      },
    });
    expect(ceiling.source).toBe('oidc-microsoft-roles');
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
  });
});

// ─── AbaxxOne Ceiling Resolver ────────────────────────────────────

describe('resolveScopeCeilingFromClaims — AbaxxOne paths', () => {
  it('extracts scope from abaxx:scope object', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://one.abaxx.tech/realms/main',
        'abaxx:scope': {
          columns: ['ticker', 'side', 'quantity'],
          actions: ['read', 'write'],
        },
      },
    });
    expect(ceiling.source).toBe('oidc-abaxxone');
    expect(ceiling.columns).toEqual(['ticker', 'side', 'quantity']);
    expect(ceiling.actions).toEqual(['read', 'write']);
    expect(ceiling.resolvedFrom).toEqual(['abaxx:scope']);
  });

  it('strips wildcards from abaxx:scope', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://one.abaxx.tech/realms/main',
        'abaxx:scope': {
          columns: ['*', 'ticker'],
          actions: ['*'],
        },
      },
    });
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.actions).toEqual([]);
  });

  it('falls back to scope_columns/scope_actions for AbaxxOne', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://one.abaxx.tech/realms/main',
        scope_columns: ['ticker'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.source).toBe('oidc-abaxxone');
    expect(ceiling.columns).toEqual(['ticker']);
  });

  it('returns empty ceiling (fail-closed) for AbaxxOne with no scope info', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://abaxxone.com/auth',
      },
    });
    expect(ceiling.source).toBe('oidc-abaxxone');
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
  });

  it('handles abaxx:scope with string values (single column/action)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        iss: 'https://one.abaxx.tech/realms/main',
        'abaxx:scope': {
          columns: 'ticker',
          actions: 'read',
        },
      },
    });
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.actions).toEqual(['read']);
  });
});
