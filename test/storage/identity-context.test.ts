import { createIdentityContext } from '#storage/identity-context.js';
import type { AgentVerifyResult } from '#identity/agent-verifier.js';

describe('createIdentityContext', () => {
  const mockVerifyResult: AgentVerifyResult = {
    issuerDid: 'did:key:zServer1',
    subjectDid: 'did:key:zAgent1',
    orgDomain: 'company.com',
    capabilities: [],
    credential: {
      issuer: 'did:key:zServer1',
      subject: 'did:key:zAgent1',
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
    },
  };

  it('creates IdentityContext from AgentVerifyResult', () => {
    const ctx = createIdentityContext(mockVerifyResult);

    expect(ctx.callerDid).toBe('did:key:zAgent1');
    expect(ctx.issuerDid).toBe('did:key:zServer1');
    expect(ctx.orgDomain).toBe('company.com');
    expect(ctx.verifiedAt).toBeGreaterThan(0);
  });
});
