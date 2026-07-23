import { describe, it, expect } from 'vitest';
import {
  validateScope,
  validateExpiry,
  validateChain,
  extractMaxDepth,
  resolveInheritedMaxDepth,
  DEFAULT_MAX_DELEGATION_DEPTH,
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

    it('includes parent columns in scope error message', () => {
      expect(() =>
        validateScope(
          { columns: ['ticker', 'side'], actions: ['read'] },
          { columns: ['price'], actions: ['read'] },
        ),
      ).toThrow('Delegator has: [ticker, side]');
    });

    it('throws when requested action is not in parent scope', () => {
      expect(() =>
        validateScope(
          { columns: ['ticker'], actions: ['read'] },
          { columns: ['ticker'], actions: ['write' as 'read'] },
        ),
      ).toThrow("action 'write' is not in the delegator's scope");
    });

    it('accepts empty requested scope', () => {
      expect(() =>
        validateScope({ columns: ['ticker'], actions: ['read'] }, { columns: [], actions: [] }),
      ).not.toThrow();
    });
  });

  describe('validateExpiry', () => {
    it('returns requested expiry when no parent max', () => {
      expect(validateExpiry(1000)).toBe(1000);
    });

    it('returns requested expiry when within parent max', () => {
      expect(validateExpiry(500, 1000)).toBe(500);
    });

    it('returns requested expiry when equal to parent max', () => {
      expect(validateExpiry(1000, 1000)).toBe(1000);
    });

    it('clamps to parent max when requested expiry exceeds it', () => {
      expect(validateExpiry(2000, 1000)).toBe(1000);
    });

    it('returns zero when requested expiry is zero', () => {
      expect(validateExpiry(0, 1000)).toBe(0);
    });
  });

  describe('validateChain', () => {
    it('accepts chain within max depth', () => {
      expect(() => validateChain(1, 3)).not.toThrow();
    });

    it('throws at exact max depth boundary', () => {
      expect(() => validateChain(3, 3)).toThrow('chain depth 3 exceeds maximum 3');
    });

    it('throws when chain depth exceeds max', () => {
      expect(() => validateChain(5, 3)).toThrow('chain depth 5 exceeds maximum 3');
    });

    it('blocks third hop with default maxDepth of 2', () => {
      expect(() => validateChain(1, 2)).not.toThrow();
      expect(() => validateChain(2, 2)).toThrow('chain depth 2 exceeds maximum 2');
    });
  });

  describe('extractMaxDepth', () => {
    it('returns the embedded value for positive integers', () => {
      expect(extractMaxDepth({ maxDepth: 3 })).toBe(3);
      expect(extractMaxDepth({ maxDepth: 1 })).toBe(1);
    });

    it('returns undefined when field is missing', () => {
      expect(extractMaxDepth({})).toBeUndefined();
    });

    it('returns undefined for malformed values', () => {
      expect(extractMaxDepth({ maxDepth: 0 })).toBeUndefined();
      expect(extractMaxDepth({ maxDepth: -1 })).toBeUndefined();
      expect(extractMaxDepth({ maxDepth: 1.5 })).toBeUndefined();
      expect(extractMaxDepth({ maxDepth: '3' })).toBeUndefined();
      expect(extractMaxDepth({ maxDepth: null })).toBeUndefined();
    });
  });

  describe('resolveInheritedMaxDepth', () => {
    it('returns the source ceiling when no ancestors', () => {
      expect(resolveInheritedMaxDepth({ maxDepth: 3 }, [])).toBe(3);
    });

    it('picks the most restrictive ancestor', () => {
      expect(resolveInheritedMaxDepth({ maxDepth: 5 }, [{ maxDepth: 3 }, { maxDepth: 4 }])).toBe(3);
    });

    it('treats a missing ancestor ceiling as the library default', () => {
      expect(resolveInheritedMaxDepth({ maxDepth: 5 }, [{}])).toBe(DEFAULT_MAX_DELEGATION_DEPTH);
    });

    it('treats a mixed chain with explicit and missing ancestor ceilings as capped by the default', () => {
      expect(resolveInheritedMaxDepth({ maxDepth: 5 }, [{ maxDepth: 3 }, {}])).toBe(
        DEFAULT_MAX_DELEGATION_DEPTH,
      );
    });

    it('treats a missing source ceiling as the library default even when an ancestor embeds one', () => {
      expect(resolveInheritedMaxDepth({}, [{ maxDepth: 5 }])).toBe(DEFAULT_MAX_DELEGATION_DEPTH);
    });

    it('falls back to the library default when neither source nor chain embed one', () => {
      expect(resolveInheritedMaxDepth({}, [])).toBe(DEFAULT_MAX_DELEGATION_DEPTH);
    });
  });
});
