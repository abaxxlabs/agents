import { describe, it, expect } from 'vitest';
import { DelegationExpiryExceedsParentError } from '#errors/index.js';
import {
  validateScope,
  validateExpiry,
  validateChain,
  extractMaxDepth,
  DELEGATION_POLICY_TYPE,
} from '#auth/delegation-policy.js';

describe('delegation-policy', () => {
  describe('validateScope', () => {
    it('accepts valid column and action subset', () => {
      expect(() =>
        validateScope(
          { columns: ['ticker', 'side', 'qty'], actions: ['read'] },
          { columns: ['ticker', 'side'], actions: ['read'] },
        ),
      ).not.toThrow();
    });

    it('throws when requested column is not in parent scope', () => {
      expect(() =>
        validateScope(
          { columns: ['ticker', 'side'], actions: ['read'] },
          { columns: ['ticker', 'price'], actions: ['read'] },
        ),
      ).toThrow("column 'price' is not in the delegator's scope");
    });

    it('throws when requested action is not in parent scope', () => {
      expect(() =>
        validateScope(
          { columns: ['ticker'], actions: ['read'] },
          { columns: ['ticker'], actions: ['write' as 'read'] },
        ),
      ).toThrow("action 'write' is not in the delegator's scope");
    });
  });

  describe('validateExpiry', () => {
    it('returns requested expiry when within parent max', () => {
      expect(validateExpiry(500, 1000)).toBe(500);
    });

    it('rejects when the requested expiry exceeds the parent max', () => {
      expect(() => validateExpiry(2000, 1000)).toThrow(DelegationExpiryExceedsParentError);
    });
  });

  describe('validateChain', () => {
    it('throws at exact max depth boundary', () => {
      expect(() => validateChain(3, 3)).toThrow('chain depth 3 exceeds maximum 3');
    });

    it('blocks third hop with default maxDepth of 2', () => {
      expect(() => validateChain(1, 2)).not.toThrow();
      expect(() => validateChain(2, 2)).toThrow('chain depth 2 exceeds maximum 2');
    });
  });

  describe('extractMaxDepth', () => {
    const terms = (maxDepth: unknown) => ({
      vc: { termsOfUse: [{ type: DELEGATION_POLICY_TYPE, maxDepth }] },
    });

    it('reads the ceiling from vc.termsOfUse', () => {
      expect(extractMaxDepth(terms(3))).toBe(3);
    });

    it('falls back to the legacy claim so older credentials keep verifying', () => {
      expect(extractMaxDepth({ maxDepth: 2 })).toBe(2);
    });
  });
});
