import { describe, it, expect } from 'vitest';
import {
  resolveScopeCeilingFromClaims,
  scopeFitsInCeiling,
  PolicyViolationError,
  timeOfDayRule,
  type ScopeCeiling,
  type IssuanceContext,
} from '#auth/ceiling.js';

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
});

describe('timeOfDayRule', () => {
  it('ceiling timezone takes priority over context timezone — bypass attempt blocked', () => {
    const rule = timeOfDayRule(18, 'America/Toronto', () => 20);
    const ctxWithBypassTimezone: IssuanceContext = {
      humanDid: 'did:key:zAttacker',
      requestedAt: new Date(),
      timezone: 'Pacific/Honolulu',
    };
    expect(() => rule.check(ctxWithBypassTimezone)).toThrow(PolicyViolationError);
  });
});
