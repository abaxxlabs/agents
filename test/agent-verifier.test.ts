import { describe, test, expect } from 'vitest';
import {
  AgentVerifier,
  createAgentVerifier,
  UntrustedIssuerError,
  WrongOrgError,
  AgentUnauthorizedError,
} from '#identity/agent-verifier.js';
import type { VerificationResult, DecodedCredential } from '#types/index.js';
import { createMockVcVerifier } from './mocks/vc-verifier.js';
import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';
import { CredentialInvalidError } from '#errors/index.js';
import type { CapabilitySet } from '#capability/types.js';

const TEST_ISSUER_DID = 'did:key:z6MkTestIssuer1234567890';
const TEST_AGENT_DID = 'did:key:z6MkTestAgent1234567890';
const TEST_ORG = 'company.com';

function makeDecodedCredential(overrides?: Partial<DecodedCredential>): DecodedCredential {
  return {
    issuer: TEST_ISSUER_DID,
    subject: TEST_AGENT_DID,
    issuedAt: new Date(Date.now() - 60_000),
    expiresAt: new Date(Date.now() + 3600_000),
    ...overrides,
  };
}

// Builds a test binding JWT; signature is a placeholder (VcVerifier is mocked).
function makeBindingJwt(subject?: {
  orgDomain?: string | null;
  capabilities?: CapabilitySet;
}): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');

  const credentialSubject: Record<string, unknown> = {
    id: TEST_AGENT_DID,
    oauthIssuer: 'https://accounts.google.com',
    oauthSubject: 'sub-12345',
    serverDid: TEST_ISSUER_DID,
  };

  if (subject?.orgDomain !== undefined) {
    credentialSubject['orgDomain'] = subject.orgDomain;
  } else {
    credentialSubject['orgDomain'] = TEST_ORG;
  }

  if (subject?.capabilities !== undefined) {
    credentialSubject['capabilities'] = subject.capabilities;
  }

  const payload = {
    iss: TEST_ISSUER_DID,
    sub: TEST_AGENT_DID,
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: 'test-jti-' + Math.random().toString(36).slice(2),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'IdentityBindingCredential'],
      credentialSubject,
    },
  };

  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${encodedPayload}.fakesignature`;
}

function validVcResult(credentialOverrides?: Partial<DecodedCredential>): VerificationResult {
  return {
    valid: true,
    status: 'VALID',
    credential: makeDecodedCredential(credentialOverrides),
  };
}

async function makeTrustStore(trusted: boolean = true): Promise<LocalTrustAnchorStore> {
  const store = new LocalTrustAnchorStore({
    ownServerDid: 'did:key:z6MkLocalServer1234567890',
  });
  if (trusted) {
    await store.addTrustedServer(TEST_ISSUER_DID, 'api', 'test-issuer');
  }
  return store;
}

describe('AgentVerifier — Layer 1 failures (VcVerifier rejects)', () => {
  async function verifyWithResult(result: VerificationResult): Promise<Error> {
    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: createMockVcVerifier(result),
      trustAnchorStore: store,
    });
    try {
      await verifier.verify({ bindingJwt: makeBindingJwt(), agentDid: TEST_AGENT_DID });
      throw new Error('Should have thrown');
    } catch (e) {
      return e as Error;
    }
  }

  test('INVALID_SIGNATURE → CredentialInvalidError', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'INVALID_SIGNATURE',
      error: 'JWT signature verification failed',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect((err as CredentialInvalidError).code).toBe('CREDENTIAL_INVALID');
    expect(err.message).toContain('INVALID_SIGNATURE');
  });

  test('REVOKED → CredentialInvalidError with [REVOKED] prefix', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'REVOKED',
      error: 'Credential has been revoked',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect(err.message).toContain('REVOKED');
  });
});

describe('AgentVerifier — Layer 2a: trust anchor check', () => {
  test('throws UntrustedIssuerError when issuer is not in trust store', async () => {
    const store = await makeTrustStore(false);
    const verifier = createAgentVerifier({
      vcVerifier: createMockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    await expect(
      verifier.verify({ bindingJwt: makeBindingJwt(), agentDid: TEST_AGENT_DID }),
    ).rejects.toBeInstanceOf(UntrustedIssuerError);
  });
});

describe('AgentVerifier — Layer 2b: org boundary check', () => {
  async function makeVerifier(trusted = true): Promise<AgentVerifier> {
    const store = await makeTrustStore(trusted);
    return createAgentVerifier({
      vcVerifier: createMockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
  }

  test('throws WrongOrgError when orgDomain does not match expectedOrg', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: 'other.com' }),
        agentDid: TEST_AGENT_DID,
        expectedOrg: 'company.com',
      }),
    ).rejects.toBeInstanceOf(WrongOrgError);
  });
});

describe('AgentVerifier — Layer 2c: capability check', () => {
  const TEST_CAPS: CapabilitySet = [
    { action: 'jira:read', scope: 'project/PROJ' },
    { action: 'github:read' },
  ];

  async function makeVerifier(): Promise<AgentVerifier> {
    const store = await makeTrustStore();
    return createAgentVerifier({
      vcVerifier: createMockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
  }

  test('throws AgentUnauthorizedError when scope does not match', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:read',
        scope: 'project/OTHER',
      }),
    ).rejects.toBeInstanceOf(AgentUnauthorizedError);
  });
});
