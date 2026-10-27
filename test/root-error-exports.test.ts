import { describe, expect, it } from 'vitest';
import { AgentScopeError, DelegationExpiryExceedsParentError } from '@abaxxlabs/agents';
import { validateExpiry } from '#auth/delegation-policy.js';

describe('package root error exports', () => {
  it('exports the class the delegation policy throws, so instanceof works for consumers', () => {
    expect(() => validateExpiry(2000, 1000)).toThrow(DelegationExpiryExceedsParentError);
    expect(new DelegationExpiryExceedsParentError(2000, 1000)).toBeInstanceOf(AgentScopeError);
  });
});
