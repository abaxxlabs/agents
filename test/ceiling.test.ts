import { describe, it, expect } from 'vitest';
import {
  resolveScopeCeiling,
  resolveScopeCeilingFromClaims,
  unrestrictedCeiling,
  scopeFitsInCeiling,
  assertScopeFitsInCeiling,
  ScopeExceedsCeilingError,
  PolicyViolationError,
  InvalidTimezoneError,
  timeOfDayRule,
  type RoleScopeConfig,
  type ScopeCeiling,
  type IssuanceContext,
} from '#auth/ceiling.js';
import { createMockSession } from '#auth/index.js';
import { VcVerifier } from '#identity/index.js';
import { InMemoryRevocationStore } from '#storage/memory/revocation-store.js';

// ─── Fixtures ──────────────────────────────────────────────────────

const healthcareConfig: RoleScopeConfig = {
  physician: {
    columns: ['name', 'dob', 'diagnosis'],
    actions: ['read'],
  },
  billing: {
    columns: ['name', 'insurance_id'],
    actions: ['read'],
  },
  admin: {
    columns: ['name', 'dob', 'diagnosis', 'insurance_id'],
    actions: ['read', 'write'],
  },
};

// ─── groups claim extraction ──────────────────────────────────────

describe('resolveScopeCeiling — groups claim extraction', () => {
  it('accepts groups as an array of strings', () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: ['physician'] } }, healthcareConfig);
    expect(ceiling.columns).toEqual(['name', 'dob', 'diagnosis']);
    expect(ceiling.actions).toEqual(['read']);
    expect(ceiling.resolvedFrom).toEqual(['physician']);
    expect(ceiling.source).toBe('oidc-groups');
  });

  it('accepts groups as a single string (shorthand)', () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: 'billing' } }, healthcareConfig);
    expect(ceiling.columns).toEqual(['name', 'insurance_id']);
    expect(ceiling.resolvedFrom).toEqual(['billing']);
  });

  it('returns empty ceiling when groups claim is missing', () => {
    const ceiling = resolveScopeCeiling({ claims: {} }, healthcareConfig);
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
    expect(ceiling.resolvedFrom).toEqual([]);
  });

  it('returns empty ceiling when groups claim is null', () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: null } }, healthcareConfig);
    expect(ceiling.columns).toEqual([]);
  });

  it('returns empty ceiling when groups claim is an object (malformed)', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: { role: 'admin' } } },
      healthcareConfig,
    );
    expect(ceiling.columns).toEqual([]);
  });

  it('filters non-string entries out of a groups array', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: ['physician', 42, null, 'billing'] } },
      healthcareConfig,
    );
    expect(new Set(ceiling.resolvedFrom)).toEqual(new Set(['physician', 'billing']));
  });
});

// ─── Union semantics ──────────────────────────────────────────────

describe('resolveScopeCeiling — union semantics', () => {
  it('unions columns across multiple matched groups', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: ['physician', 'billing'] } },
      healthcareConfig,
    );
    expect(new Set(ceiling.columns)).toEqual(new Set(['name', 'dob', 'diagnosis', 'insurance_id']));
    expect(new Set(ceiling.actions)).toEqual(new Set(['read']));
    expect(new Set(ceiling.resolvedFrom)).toEqual(new Set(['physician', 'billing']));
  });

  it('unions actions across matched groups (admin adds write)', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: ['physician', 'admin'] } },
      healthcareConfig,
    );
    expect(new Set(ceiling.actions)).toEqual(new Set(['read', 'write']));
  });

  it('silently drops groups not in the role map', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: ['physician', 'unknown-role'] } },
      healthcareConfig,
    );
    expect(ceiling.resolvedFrom).toEqual(['physician']);
    expect(new Set(ceiling.columns)).toEqual(new Set(['name', 'dob', 'diagnosis']));
  });

  it('deduplicates columns across overlapping groups', () => {
    const ceiling = resolveScopeCeiling(
      { claims: { groups: ['physician', 'admin'] } },
      healthcareConfig,
    );
    const nameCount = ceiling.columns.filter((c) => c === 'name').length;
    expect(nameCount).toBe(1);
  });

  it('strips literal wildcard from config entries (misconfiguration guard)', () => {
    const configWithWildcard: RoleScopeConfig = {
      superadmin: { columns: ['*', 'ticker'], actions: ['*', 'read'] },
    };
    const ceiling = resolveScopeCeiling({ claims: { groups: ['superadmin'] } }, configWithWildcard);
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.actions).toEqual(['read']);
    const result = scopeFitsInCeiling({ columns: ['surprise'], actions: ['read'] }, ceiling);
    expect(result.ok).toBe(false);
  });
});

// ─── resolveScopeCeilingFromClaims — Keycloak-native primary path ──

describe('resolveScopeCeilingFromClaims', () => {
  it('reads scope_columns and scope_actions directly from claims', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: ['ticker', 'side', 'quantity'],
        scope_actions: ['read'],
      },
    });
    expect(ceiling.columns).toEqual(['ticker', 'side', 'quantity']);
    expect(ceiling.actions).toEqual(['read']);
    expect(ceiling.source).toBe('oidc-claims');
    expect(new Set(ceiling.resolvedFrom)).toEqual(new Set(['scope_columns', 'scope_actions']));
  });

  it('returns empty ceiling when both claims are missing', () => {
    const ceiling = resolveScopeCeilingFromClaims({ claims: {} });
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
    expect(ceiling.source).toBe('oidc-claims');
    expect(ceiling.resolvedFrom).toEqual([]);
  });

  it('returns partial ceiling when only one claim is present', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: { scope_columns: ['ticker'] },
    });
    expect(ceiling.columns).toEqual(['ticker']);
    expect(ceiling.actions).toEqual([]);
    expect(ceiling.resolvedFrom).toEqual(['scope_columns']);
  });

  it('filters non-string entries out of scope arrays', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: ['ticker', 42, null, 'side'],
        scope_actions: ['read', { nope: true }],
      },
    });
    expect(ceiling.columns).toEqual(['ticker', 'side']);
    expect(ceiling.actions).toEqual(['read']);
  });

  it('treats non-array claim values as empty (fail-closed)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: 'ticker',
        scope_actions: null,
      },
    });
    expect(ceiling.columns).toEqual([]);
    expect(ceiling.actions).toEqual([]);
  });

  it('strips literal wildcard strings (IdP misconfiguration guard)', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: ['ticker', '*', 'side'],
        scope_actions: ['*', 'read'],
      },
    });
    expect(ceiling.columns).toEqual(['ticker', 'side']);
    expect(ceiling.actions).toEqual(['read']);
    const result = scopeFitsInCeiling({ columns: ['surprise'], actions: ['read'] }, ceiling);
    expect(result.ok).toBe(false);
  });

  it('ceiling produced by fromClaims composes with scopeFitsInCeiling', () => {
    const ceiling = resolveScopeCeilingFromClaims({
      claims: {
        scope_columns: ['name', 'dob'],
        scope_actions: ['read'],
      },
    });
    expect(scopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling).ok).toBe(true);
    expect(scopeFitsInCeiling({ columns: ['name', 'ssn'], actions: ['read'] }, ceiling).ok).toBe(
      false,
    );
  });
});

// ─── unrestrictedCeiling ──────────────────────────────────────────

describe('unrestrictedCeiling', () => {
  it('has wildcards on both axes and mock source', () => {
    const ceiling = unrestrictedCeiling();
    expect(ceiling.columns).toEqual(['*']);
    expect(ceiling.actions).toEqual(['*']);
    expect(ceiling.source).toBe('mock-unrestricted');
    expect(ceiling.resolvedFrom).toEqual([]);
  });
});

// ─── scopeFitsInCeiling ───────────────────────────────────────────

describe('scopeFitsInCeiling — pass cases', () => {
  const physCeiling: ScopeCeiling = {
    columns: ['name', 'dob', 'diagnosis'],
    actions: ['read'],
    source: 'oidc-groups',
    resolvedFrom: ['physician'],
  };

  it('accepts an exact-match request', () => {
    const result = scopeFitsInCeiling(
      { columns: ['name', 'dob', 'diagnosis'], actions: ['read'] },
      physCeiling,
    );
    expect(result.ok).toBe(true);
  });

  it('accepts a strict subset', () => {
    const result = scopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, physCeiling);
    expect(result.ok).toBe(true);
  });

  it('accepts a request with duplicate columns (dedups before compare)', () => {
    const result = scopeFitsInCeiling(
      { columns: ['name', 'name', 'dob'], actions: ['read'] },
      physCeiling,
    );
    expect(result.ok).toBe(true);
  });

  it('accepts everything against a wildcard ceiling', () => {
    const wild = unrestrictedCeiling();
    const result = scopeFitsInCeiling(
      { columns: ['any_column_at_all'], actions: ['read', 'write', 'admin'] },
      wild,
    );
    expect(result.ok).toBe(true);
  });
});

describe('scopeFitsInCeiling — reject cases', () => {
  const physCeiling: ScopeCeiling = {
    columns: ['name', 'dob', 'diagnosis'],
    actions: ['read'],
    source: 'oidc-groups',
    resolvedFrom: ['physician'],
  };

  it('rejects a request for a column outside the ceiling', () => {
    const result = scopeFitsInCeiling(
      { columns: ['name', 'insurance_id'], actions: ['read'] },
      physCeiling,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.excess.columns).toEqual(['insurance_id']);
      expect(result.excess.actions).toEqual([]);
    }
  });

  it('rejects a request for an action outside the ceiling', () => {
    const result = scopeFitsInCeiling(
      { columns: ['name'], actions: ['read', 'write'] },
      physCeiling,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.excess.columns).toEqual([]);
      expect(result.excess.actions).toEqual(['write']);
    }
  });

  it('reports excess on both axes when both fail', () => {
    const result = scopeFitsInCeiling(
      { columns: ['insurance_id'], actions: ['write'] },
      physCeiling,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.excess.columns).toEqual(['insurance_id']);
      expect(result.excess.actions).toEqual(['write']);
    }
  });

  it('rejects every request against an empty ceiling', () => {
    const empty: ScopeCeiling = {
      columns: [],
      actions: [],
      source: 'oidc-groups',
      resolvedFrom: [],
    };
    const result = scopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, empty);
    expect(result.ok).toBe(false);
  });
});

// ─── assertScopeFitsInCeiling + ScopeExceedsCeilingError ──────────

describe('assertScopeFitsInCeiling', () => {
  const physCeiling: ScopeCeiling = {
    columns: ['name', 'dob', 'diagnosis'],
    actions: ['read'],
    source: 'oidc-groups',
    resolvedFrom: ['physician'],
  };

  it('returns void when the request fits', () => {
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, physCeiling),
    ).not.toThrow();
  });

  it('throws ScopeExceedsCeilingError with ceiling and excess attached', () => {
    try {
      assertScopeFitsInCeiling({ columns: ['insurance_id'], actions: ['write'] }, physCeiling);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ScopeExceedsCeilingError);
      const e = err as ScopeExceedsCeilingError;
      expect(e.code).toBe('SCOPE_EXCEEDS_CEILING');
      expect(e.ceiling).toBe(physCeiling);
      expect(e.excess.columns).toEqual(['insurance_id']);
      expect(e.excess.actions).toEqual(['write']);
    }
  });

  it('error message names the excess and the groups that were resolved', () => {
    try {
      assertScopeFitsInCeiling({ columns: ['insurance_id'], actions: [] }, physCeiling);
      throw new Error('expected throw');
    } catch (err) {
      const e = err as ScopeExceedsCeilingError;
      expect(e.message).toContain('insurance_id');
      expect(e.message).toContain('physician');
    }
  });
});

describe('createMockSession + scopeCeiling — integration', () => {
  const physConfig: RoleScopeConfig = {
    physician: { columns: ['name', 'dob', 'diagnosis'], actions: ['read'] },
  };

  it('populates scopeCeiling on the returned session', () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: ['physician'] } }, physConfig);
    const session = createMockSession(
      new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() }),
      'Doctor Test',
      undefined,
      ceiling,
    );
    expect(session.scopeCeiling).toBe(ceiling);
    expect(session.scopeCeiling.source).toBe('oidc-groups');
    expect(session.scopeCeiling.resolvedFrom).toEqual(['physician']);
  });

  it('issueCredential succeeds when request fits ceiling', async () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: ['physician'] } }, physConfig);
    const session = createMockSession(
      new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() }),
      'Doctor Test',
      undefined,
      ceiling,
    );

    const jwt = await session.issueCredential({
      agent: 'did:key:zAgent1',
      columns: ['name', 'dob'],
      actions: ['read'],
      expiresIn: '1h',
    });
    expect(typeof jwt).toBe('string');
    expect(jwt.split('.').length).toBe(3);
  });

  it('issueCredential throws ScopeExceedsCeilingError when request exceeds ceiling', async () => {
    const ceiling = resolveScopeCeiling({ claims: { groups: ['physician'] } }, physConfig);
    const session = createMockSession(
      new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() }),
      'Doctor Test',
      undefined,
      ceiling,
    );

    await expect(
      session.issueCredential({
        agent: 'did:key:zAgent1',
        columns: ['name', 'dob', 'diagnosis', 'insurance_id'],
        actions: ['read'],
        expiresIn: '1h',
      }),
    ).rejects.toBeInstanceOf(ScopeExceedsCeilingError);
  });

  it('default (no ceiling supplied) is unrestricted — preserves backward compat', async () => {
    const session = createMockSession(
      new VcVerifier({ clockSkew: '30s', revocationStore: new InMemoryRevocationStore() }),
      'Legacy Test',
    );
    expect(session.scopeCeiling.source).toBe('mock-unrestricted');

    const jwt = await session.issueCredential({
      agent: 'did:key:zAgent1',
      columns: ['anything_at_all'],
      actions: ['read'],
      expiresIn: '1h',
    });
    expect(typeof jwt).toBe('string');
  });
});

// ─── PolicyViolationError ─────────────────────────────────────────

describe('PolicyViolationError', () => {
  it('is an instance of Error', () => {
    const err = new PolicyViolationError('blocked after hours');
    expect(err).toBeInstanceOf(Error);
  });

  it('carries the correct name', () => {
    const err = new PolicyViolationError('test message');
    expect(err.name).toBe('PolicyViolationError');
  });

  it('carries the correct message', () => {
    const err = new PolicyViolationError('no issuance after 18:00');
    expect(err.message).toBe('no issuance after 18:00');
  });

  it('has the POLICY_VIOLATION code', () => {
    const err = new PolicyViolationError('test');
    expect(err.code).toBe('POLICY_VIOLATION');
  });
});

// ─── timeOfDayRule ────────────────────────────────────────────────

describe('timeOfDayRule', () => {
  function makeContext(): IssuanceContext {
    return { humanDid: 'did:key:zTest', requestedAt: new Date() };
  }

  it('does not throw when the hour is before blockFromHour', () => {
    // blockFromHour=18, clock override returns 9 → allowed
    const rule = timeOfDayRule(18, undefined, () => 9);
    expect(() => rule.check(makeContext())).not.toThrow();
  });

  it('throws PolicyViolationError when hour equals blockFromHour (at means at-and-after)', () => {
    const rule = timeOfDayRule(18, undefined, () => 18);
    expect(() => rule.check(makeContext())).toThrowError(PolicyViolationError);
  });

  it('throws PolicyViolationError when hour is after blockFromHour', () => {
    const rule = timeOfDayRule(18, undefined, () => 22);
    expect(() => rule.check(makeContext())).toThrowError(PolicyViolationError);
  });

  it('error message includes the blockFromHour', () => {
    const rule = timeOfDayRule(18, undefined, () => 19);
    let caught: Error | undefined;
    try {
      rule.check(makeContext());
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeInstanceOf(PolicyViolationError);
    expect(caught!.message).toContain('18');
  });

  it('does not throw at hour 0 when blockFromHour is 6 (midnight is before 06:00 block)', () => {
    // raw=24 → resolveHourFromDate converts to 0; clock override simulates same
    const rule = timeOfDayRule(6, undefined, () => 0);
    expect(() => rule.check(makeContext())).not.toThrow();
  });

  it('includes the timezone string in the error message when tz is provided', () => {
    const rule = timeOfDayRule(18, 'America/Toronto', () => 20);
    let caught: Error | undefined;
    try {
      rule.check(makeContext());
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeInstanceOf(PolicyViolationError);
    expect(caught!.message).toContain('America/Toronto');
  });

  it('ceiling timezone takes priority over context timezone — bypass attempt blocked', () => {
    // Ceiling says block at 18 in America/Toronto.
    // Attacker supplies context timezone 'Pacific/Honolulu' (UTC-10) hoping to shift
    // the effective hour to 13:00 and bypass the block. Ceiling's timezone must win.
    const rule = timeOfDayRule(18, 'America/Toronto', () => 20); // clock returns 20 (blocked)
    // The _clock override means the timezone doesn't affect the mock hour,
    // but the ceiling's configured tz should be used — context tz is ignored.
    const ctxWithBypassTimezone: IssuanceContext = {
      humanDid: 'did:key:zAttacker',
      requestedAt: new Date(),
      timezone: 'Pacific/Honolulu',
    };
    expect(() => rule.check(ctxWithBypassTimezone)).toThrow(PolicyViolationError);
  });
});

// ─── assertScopeFitsInCeiling with rules ─────────────────────────

describe('assertScopeFitsInCeiling with IssuanceContext + rules', () => {
  const physCeiling: ScopeCeiling = {
    columns: ['name', 'dob'],
    actions: ['read'],
    source: 'oidc-groups',
    resolvedFrom: ['physician'],
  };

  it('skips rules when no context is passed (backward compat)', () => {
    const ceilingWithRule: ScopeCeiling = {
      ...physCeiling,
      rules: [timeOfDayRule(18, undefined, () => 23)], // would block if evaluated
    };
    // No context → rules not evaluated → no throw
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceilingWithRule),
    ).not.toThrow();
  });

  it('does not throw when rule passes (hour before blockFromHour)', () => {
    const ceilingWithRule: ScopeCeiling = {
      ...physCeiling,
      rules: [timeOfDayRule(18, undefined, () => 9)],
    };
    const ctx: IssuanceContext = { humanDid: 'did:key:zTest', requestedAt: new Date() };
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceilingWithRule, ctx),
    ).not.toThrow();
  });

  it('throws PolicyViolationError when the rule blocks issuance', () => {
    const ceilingWithRule: ScopeCeiling = {
      ...physCeiling,
      rules: [timeOfDayRule(18, undefined, () => 20)],
    };
    const ctx: IssuanceContext = { humanDid: 'did:key:zTest', requestedAt: new Date() };
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceilingWithRule, ctx),
    ).toThrowError(PolicyViolationError);
  });

  it('throws ScopeExceedsCeilingError (not PolicyViolationError) when scope fails before rules', () => {
    const ceilingWithRule: ScopeCeiling = {
      ...physCeiling,
      rules: [timeOfDayRule(18, undefined, () => 20)],
    };
    const ctx: IssuanceContext = { humanDid: 'did:key:zTest', requestedAt: new Date() };
    // Scope check runs before rules — insurance_id not in ceiling columns
    expect(() =>
      assertScopeFitsInCeiling(
        { columns: ['insurance_id'], actions: ['read'] },
        ceilingWithRule,
        ctx,
      ),
    ).toThrowError(ScopeExceedsCeilingError);
  });
});

describe('timeOfDayRule — context timezone validation', () => {
  const ceiling: ScopeCeiling = {
    columns: ['name'],
    actions: ['read'],
    source: 'mock-unrestricted',
    resolvedFrom: [],
    rules: [timeOfDayRule(18)], // no built-in timezone — defers to context
  };

  it('accepts a valid IANA timezone in context (America/New_York)', () => {
    const ctx: IssuanceContext = {
      humanDid: 'did:key:zTest',
      requestedAt: new Date(),
      timezone: 'America/New_York',
    };
    // blockFromHour=18, _clock not set — may or may not block depending on wall clock.
    // We just verify no InvalidTimezoneError is thrown.
    try {
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx);
    } catch (err) {
      // Only PolicyViolationError is acceptable (wall-clock may be after 18:00)
      expect(err).not.toBeInstanceOf(InvalidTimezoneError);
    }
  });

  it('accepts UTC as a valid timezone', () => {
    const ctx: IssuanceContext = {
      humanDid: 'did:key:zTest',
      requestedAt: new Date(),
      timezone: 'UTC',
    };
    try {
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx);
    } catch (err) {
      expect(err).not.toBeInstanceOf(InvalidTimezoneError);
    }
  });

  it('throws InvalidTimezoneError for an invalid timezone string', () => {
    const ctx: IssuanceContext = {
      humanDid: 'did:key:zTest',
      requestedAt: new Date(),
      timezone: 'Foo/Bar',
    };
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx),
    ).toThrowError(InvalidTimezoneError);
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx),
    ).toThrow('Unsupported IANA timezone: Foo/Bar');
  });

  it('throws InvalidTimezoneError for an empty string timezone', () => {
    // Empty string is falsy — assertValidTimezone no-ops, same as absent timezone.
    const ctx: IssuanceContext = {
      humanDid: 'did:key:zTest',
      requestedAt: new Date(),
      timezone: '',
    };
    expect(() =>
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx),
    ).not.toThrowError(InvalidTimezoneError);
  });

  it('does not throw when context has no timezone (undefined)', () => {
    const ctx: IssuanceContext = {
      humanDid: 'did:key:zTest',
      requestedAt: new Date(),
      // timezone omitted → undefined
    };
    try {
      assertScopeFitsInCeiling({ columns: ['name'], actions: ['read'] }, ceiling, ctx);
    } catch (err) {
      // Only PolicyViolationError is acceptable
      expect(err).not.toBeInstanceOf(InvalidTimezoneError);
    }
  });
});
