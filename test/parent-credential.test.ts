import { describe, it, expect, vi } from 'vitest';
import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';
import { createSessionFromDid } from '#auth/agent.js';
import { createOidcSession } from '#auth/session-factory.js';
import { VcVerifier } from '#identity/index.js';
import { AgentVerifier, ParentScopeExceededError } from '#identity/agent-verifier.js';
import { CapabilityEngine } from '#capability/engine.js';
import { generateDidKey } from '#auth/index.js';
import { ParentCredentialRequestFailedError } from '#errors/index.js';
import type { CapabilitySet } from '#capability/types.js';
import type { IdSdkInstance } from '#types/id-sdk.js';
import { createMockVcVerifier } from './mocks/vc-verifier.js';

const OWN_DID = 'did:key:z6MkownServerTest123';
const PARENT_DID = 'did:dht:parentOrgInstance456';
const AGENT_DID = 'did:key:z6MkagentTest789';
const ISSUER_DID = 'did:key:z6MkTestIssuer1234567890';
const PARENT_TENANT_URL = 'https://parent.example.com';

function makeParentProvider(response: { jwt: string; issuerDid: string }) {
  return {
    requestAgentCredential: vi.fn().mockResolvedValue(response),
  };
}

function makeFailingProvider(error: Error) {
  return {
    requestAgentCredential: vi.fn().mockRejectedValue(error),
  };
}

function makeLogger() {
  return { warn: vi.fn(), error: vi.fn() };
}

function makeBindingJwt(capabilities?: CapabilitySet): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payload = {
    iss: ISSUER_DID,
    sub: AGENT_DID,
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: 'test-jti-' + Math.random().toString(36).slice(2),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'IdentityBindingCredential'],
      credentialSubject: {
        id: AGENT_DID,
        oauthIssuer: 'https://accounts.google.com',
        oauthSubject: 'sub-12345',
        serverDid: ISSUER_DID,
        orgDomain: 'test.com',
        ...(capabilities !== undefined && { capabilities }),
      },
    },
  };
  return `${header}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.fakesignature`;
}

describe('createSessionFromDid — parent credential failure', () => {
  const humanKeys = generateDidKey();

  it('propagates the parent error unchanged and signs nothing locally', async () => {
    const parentError = new ParentCredentialRequestFailedError(
      PARENT_TENANT_URL,
      503,
      'network timeout',
    );
    const provider = makeFailingProvider(parentError);
    const logger = makeLogger();

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier,
      undefined,
      undefined,
      humanKeys.privateKey,
      undefined,
      {
        provider,
        accessToken: 'token-123',
        issuerDid: PARENT_DID,
        credentialExp: Math.floor(Date.now() / 1000) + 3600,
      },
      logger,
    );

    await expect(
      session.issueCredential({
        agent: AGENT_DID,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      }),
    ).rejects.toBe(parentError);

    expect(provider.requestAgentCredential).toHaveBeenCalledTimes(1);
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('network timeout'), {
      tenantUrl: PARENT_TENANT_URL,
      upstreamStatus: 503,
    });
  });

  it('does not fall back to SDK signing when the parent fails', async () => {
    const provider = makeFailingProvider(
      new ParentCredentialRequestFailedError(PARENT_TENANT_URL, 403, 'not authorized'),
    );
    const sdk = {
      vc: {
        createCredential: vi.fn(),
        getSignerOptions: vi.fn(),
        signCredential: vi.fn(),
      },
    };

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier,
      sdk as unknown as IdSdkInstance,
      undefined,
      undefined,
      undefined,
      {
        provider,
        accessToken: 'token-123',
        issuerDid: PARENT_DID,
        credentialExp: Math.floor(Date.now() / 1000) + 3600,
      },
      makeLogger(),
    );

    await expect(
      session.issueCredential({
        agent: AGENT_DID,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      }),
    ).rejects.toThrow(ParentCredentialRequestFailedError);

    expect(sdk.vc.createCredential).not.toHaveBeenCalled();
    expect(sdk.vc.getSignerOptions).not.toHaveBeenCalled();
    expect(sdk.vc.signCredential).not.toHaveBeenCalled();
  });
});

describe('createSessionFromDid — requireParent', () => {
  const humanKeys = generateDidKey();

  it('throws when requireParent is set but no parent provider configured', async () => {
    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier,
      undefined,
      undefined,
      humanKeys.privateKey,
    );

    await expect(
      session.issueCredential({
        agent: AGENT_DID,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
        requireParent: true,
      }),
    ).rejects.toThrow('requireParent is set');
  });
});

describe('createSessionFromDid — revokeCredential', () => {
  it('store write failure propagates as hard failure (no silent continue)', async () => {
    const humanKeys = generateDidKey();

    const { InMemoryRevocationStore } = await import('../src/storage/memory/revocation-store.js');
    const failingStore = new InMemoryRevocationStore();
    vi.spyOn(failingStore, 'revoke').mockRejectedValue(new Error('storage write failed'));

    const realVerifier = new VcVerifier({ revocationStore: failingStore });

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      realVerifier,
      undefined,
      undefined,
      humanKeys.privateKey,
    );

    await expect(session.revokeCredential('some-jti-d10-hard-fail')).rejects.toThrow(
      'storage write failed',
    );
  });
});

describe('AgentVerifier — Step 2.5 parentScopeCeiling', () => {
  async function makeVerifier() {
    const trustStore = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await trustStore.addTrustedServer(ISSUER_DID, 'api');

    return new AgentVerifier({
      vcVerifier: createMockVcVerifier({
        valid: true,
        status: 'VALID',
        credential: {
          issuer: ISSUER_DID,
          subject: AGENT_DID,
          issuedAt: new Date(Date.now() - 60_000),
          expiresAt: new Date(Date.now() + 3600_000),
        },
      }),
      trustAnchorStore: trustStore,
      capabilityEngine: new CapabilityEngine(),
    });
  }

  it('throws ParentScopeExceededError when capabilities exceed ceiling', async () => {
    const verifier = await makeVerifier();
    const caps: CapabilitySet = [
      { scope: 'data:patients', action: 'read' },
      { scope: 'data:secrets', action: 'write' },
    ];
    const ceiling: CapabilitySet = [{ scope: 'data:patients', action: 'read' }];

    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt(caps),
        agentDid: AGENT_DID,
        parentScopeCeiling: ceiling,
      }),
    ).rejects.toThrow(ParentScopeExceededError);
  });
});

describe('createOidcSession — parent issuance', () => {
  const identity = {
    humanDid: 'did:key:z6MkoidcHumanTest111',
    issuer: 'https://tenant.example',
    sub: 'user-123',
    email: 'trader@tenant.example',
  };

  function makeVerifier() {
    return { registerKey: vi.fn() } as unknown as VcVerifier;
  }

  it('asks the tenant to sign until the parent credential expires, then rejects without calling the provider', async () => {
    const provider = makeParentProvider({ jwt: 'tenant.signed.jwt', issuerDid: PARENT_DID });
    const credentialExp = Math.floor(Date.now() / 1000) + 3600;
    const session = createOidcSession(makeVerifier(), identity, undefined, undefined, undefined, {
      provider,
      accessToken: 'access-token',
      credentialExp,
    });

    const jwt = await session.issueCredential({
      agent: AGENT_DID,
      columns: ['order_book.ticker'],
      actions: ['read'],
      expiresIn: '4h',
    });

    expect(jwt).toBe('tenant.signed.jwt');
    expect(provider.requestAgentCredential).toHaveBeenCalledWith(
      'access-token',
      AGENT_DID,
      expect.objectContaining({
        columns: ['order_book.ticker'],
        actions: ['read'],
        expiresIn: '4h',
      }),
    );

    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue((credentialExp + 1) * 1000);
    try {
      await expect(
        session.issueCredential({
          agent: AGENT_DID,
          columns: ['order_book.ticker'],
          actions: ['read'],
          expiresIn: '4h',
        }),
      ).rejects.toThrow(/expired/i);
      expect(provider.requestAgentCredential).toHaveBeenCalledTimes(1);
    } finally {
      nowSpy.mockRestore();
    }
  });
});
