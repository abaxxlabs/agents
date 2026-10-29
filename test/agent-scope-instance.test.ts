import { describe, expectTypeOf, it } from 'vitest';
import type { AuthenticatedSession, AuthorizationUrlResult } from '@abaxxlabs/agents';
import type { AgentScopeInstance } from '@abaxxlabs/agents/sql';

describe('AgentScopeInstance', () => {
  it('exposes the browser OIDC flow', () => {
    expectTypeOf<AgentScopeInstance['buildAuthorizationUrl']>()
      .parameter(0)
      .toEqualTypeOf<{ redirectUri?: string } | undefined>();
    expectTypeOf<
      AgentScopeInstance['buildAuthorizationUrl']
    >().returns.resolves.toEqualTypeOf<AuthorizationUrlResult>();
    expectTypeOf<AgentScopeInstance['completeAuthentication']>().parameters.toEqualTypeOf<
      [authorizationCode: string, state: string, codeVerifier: string]
    >();
    expectTypeOf<
      AgentScopeInstance['completeAuthentication']
    >().returns.resolves.toEqualTypeOf<AuthenticatedSession>();
  });
});
