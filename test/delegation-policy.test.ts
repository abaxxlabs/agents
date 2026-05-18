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

import { describe, it, expect } from 'vitest';
import { validateScope, validateExpiry, validateChain } from '../src/auth/delegation-policy.js';

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
        validateScope(
          { columns: ['ticker'], actions: ['read'] },
          { columns: [], actions: [] },
        ),
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
      expect(() => validateChain(3, 3)).toThrow(
        'chain depth 3 exceeds maximum 3',
      );
    });

    it('throws when chain depth exceeds max', () => {
      expect(() => validateChain(5, 3)).toThrow(
        'chain depth 5 exceeds maximum 3',
      );
    });

    it('blocks third hop with default maxDepth of 2', () => {
      expect(() => validateChain(1, 2)).not.toThrow();
      expect(() => validateChain(2, 2)).toThrow(
        'chain depth 2 exceeds maximum 2',
      );
    });
  });
});
