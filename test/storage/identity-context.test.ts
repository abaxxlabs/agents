import {
  createIdentityContext,
  createServerIdentityContext,
} from '../../src/storage/identity-context.js';
import type { AgentVerifyResult } from '../../src/identity/agent-verifier.js';

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

  it('object is frozen', () => {
    const ctx = createIdentityContext(mockVerifyResult);
    expect(Object.isFrozen(ctx)).toBe(true);
  });

  it('throws on empty subjectDid', () => {
    expect(() => createIdentityContext({ ...mockVerifyResult, subjectDid: '' })).toThrow(
      /subjectDid/,
    );
  });

  it('preserves null orgDomain', () => {
    const ctx = createIdentityContext({ ...mockVerifyResult, orgDomain: null });
    expect(ctx.orgDomain).toBeNull();
  });
});

describe('createServerIdentityContext', () => {
  it('creates server identity with callerDid === issuerDid', () => {
    const ctx = createServerIdentityContext('did:key:zMyServer');

    expect(ctx.callerDid).toBe('did:key:zMyServer');
    expect(ctx.issuerDid).toBe('did:key:zMyServer');
    expect(ctx.callerDid).toBe(ctx.issuerDid); // The bypass condition
    expect(ctx.orgDomain).toBeNull();
  });

  it('object is frozen', () => {
    const ctx = createServerIdentityContext('did:key:zMyServer');
    expect(Object.isFrozen(ctx)).toBe(true);
  });

  it('throws on empty serverDid', () => {
    expect(() => createServerIdentityContext('')).toThrow(/serverDid/);
  });
});
