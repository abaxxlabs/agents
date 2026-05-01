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

// Tests for AgentVerifier: four-check sequence and all error paths.

import { describe, test, expect } from 'vitest';
import {
  AgentVerifier,
  createAgentVerifier,
  UntrustedIssuerError,
  WrongOrgError,
  AgentUnauthorizedError,
  type AgentVerifyResult,
  type AgentVerifier,
} from '../src/identity/agent-verifier.js';
import type { VcVerifier } from '../src/vc-verifier.js';
import type { VerificationResult, DecodedCredential } from '../src/types.js';
import { LocalTrustAnchorStore } from '../src/discovery/trust-anchor.js';
import { CapabilityEngine } from '../src/capability/engine.js';
import {
  CredentialInvalidError,
  CredentialMalformedError,
  UnknownIssuerError,
} from '../src/errors.js';
import type { CapabilitySet } from '../src/capability/types.js';
import {
  CapabilityParseError,
  CapabilitySetTooLargeError,
  MAX_CAPABILITY_SET_SIZE,
} from '../src/capability/index.js';

// ─── Test fixtures ────────────────────────────────────────────────────────────

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

function mockVcVerifier(result: VerificationResult): VcVerifier {
  return {
    verify: async (_jwt: string, _opts?: unknown): Promise<VerificationResult> => result,
  } as unknown as VcVerifier;
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

// ─── Constructor validation ───────────────────────────────────────────────────

describe('AgentVerifier — constructor', () => {
  test('throws TypeError if vcVerifier is missing', () => {
    expect(
      () =>
        new AgentVerifier({
          vcVerifier: null as unknown as VcVerifier,
          trustAnchorStore: new LocalTrustAnchorStore({ ownServerDid: 'did:key:z6MkOwn' }),
        }),
    ).toThrow(TypeError);
  });

  test('throws TypeError if trustAnchorStore is missing', async () => {
    expect(
      () =>
        new AgentVerifier({
          vcVerifier: mockVcVerifier(validVcResult()),
          trustAnchorStore: null as unknown as LocalTrustAnchorStore,
        }),
    ).toThrow(TypeError);
  });

  test('uses provided capabilityEngine', async () => {
    const engine = new CapabilityEngine();
    const store = await makeTrustStore();
    const verifier = new AgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
      capabilityEngine: engine,
    });
    expect(verifier).toBeInstanceOf(AgentVerifier);
  });

  test('creates default CapabilityEngine when not provided', async () => {
    const store = await makeTrustStore();
    const verifier = new AgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
    expect(verifier).toBeInstanceOf(AgentVerifier);
  });
});

// ─── Layer 1 failure mapping ──────────────────────────────────────────────────

describe('AgentVerifier — Layer 1 failures (VcVerifier rejects)', () => {
  async function verifyWithResult(result: VerificationResult): Promise<Error> {
    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(result),
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

  test('EXPIRED → CredentialInvalidError with [EXPIRED] prefix', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'EXPIRED',
      error: 'Credential expired at 2026-01-01T00:00:00.000Z',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect(err.message).toContain('EXPIRED');
  });

  test('MALFORMED → CredentialMalformedError', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'MALFORMED',
      error: 'Missing issuer (iss) claim',
    });
    expect(err).toBeInstanceOf(CredentialMalformedError);
    expect((err as CredentialMalformedError).code).toBe('CREDENTIAL_MALFORMED');
  });

  test('UNKNOWN_ISSUER → UnknownIssuerError', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'UNKNOWN_ISSUER',
      error: 'Cannot resolve did:key:z6MkUnknown',
    });
    expect(err).toBeInstanceOf(UnknownIssuerError);
    expect((err as UnknownIssuerError).code).toBe('UNKNOWN_ISSUER');
  });

  test('REPLAYED → CredentialInvalidError with [REPLAYED] prefix', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'REPLAYED',
      error: 'Credential jti abc has already been used',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect(err.message).toContain('REPLAYED');
  });

  test('WRONG_SUBJECT → CredentialInvalidError with [WRONG_SUBJECT] prefix', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'WRONG_SUBJECT',
      error: 'Credential subject mismatch',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect(err.message).toContain('WRONG_SUBJECT');
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

  test('SUSPENDED → CredentialInvalidError with [SUSPENDED] prefix', async () => {
    const err = await verifyWithResult({
      valid: false,
      status: 'SUSPENDED',
      error: 'Credential has been suspended',
    });
    expect(err).toBeInstanceOf(CredentialInvalidError);
    expect(err.message).toContain('SUSPENDED');
  });
});

// ─── Layer 2a: Trust anchor check ────────────────────────────────────────────

describe('AgentVerifier — Layer 2a: trust anchor check', () => {
  test('throws UntrustedIssuerError when issuer is not in trust store', async () => {
    const store = await makeTrustStore(false); // untrusted store
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    await expect(
      verifier.verify({ bindingJwt: makeBindingJwt(), agentDid: TEST_AGENT_DID }),
    ).rejects.toBeInstanceOf(UntrustedIssuerError);
  });

  test('UntrustedIssuerError has code UNTRUSTED_ISSUER and issuerDid in details', async () => {
    const store = await makeTrustStore(false);
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    let err: UntrustedIssuerError | undefined;
    try {
      await verifier.verify({ bindingJwt: makeBindingJwt(), agentDid: TEST_AGENT_DID });
    } catch (e) {
      err = e as UntrustedIssuerError;
    }

    expect(err).toBeDefined();
    expect(err!.code).toBe('UNTRUSTED_ISSUER');
    expect(err!.details?.['issuerDid']).toBe(TEST_ISSUER_DID);
  });

  test('passes when issuer DID is in the trust anchor store', async () => {
    const store = await makeTrustStore(true); // trusted
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    const result = await verifier.verify({
      bindingJwt: makeBindingJwt(),
      agentDid: TEST_AGENT_DID,
    });
    expect(result.issuerDid).toBe(TEST_ISSUER_DID);
  });

  test('passes when the own server DID is the issuer (local source)', async () => {
    const ownDid = 'did:key:z6MkLocalServer1234567890';
    const store = new LocalTrustAnchorStore({ ownServerDid: ownDid });

    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult({ issuer: ownDid })),
      trustAnchorStore: store,
    });

    const jwt = makeBindingJwt();
    const result = await verifier.verify({ bindingJwt: jwt, agentDid: TEST_AGENT_DID });
    expect(result.issuerDid).toBe(ownDid);
  });
});

// ─── Layer 2b: Org boundary check ────────────────────────────────────────────

describe('AgentVerifier — Layer 2b: org boundary check', () => {
  async function makeVerifier(trusted = true): Promise<AgentVerifier> {
    const store = await makeTrustStore(trusted);
    return createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
  }

  test('skips org check when expectedOrg is not provided', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt(),
      agentDid: TEST_AGENT_DID,
    });
    expect(result.orgDomain).toBe(TEST_ORG);
  });

  test('passes when orgDomain matches expectedOrg (exact)', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ orgDomain: 'company.com' }),
      agentDid: TEST_AGENT_DID,
      expectedOrg: 'company.com',
    });
    expect(result.orgDomain).toBe('company.com');
  });

  test('passes when orgDomain matches expectedOrg (case-insensitive)', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ orgDomain: 'Company.COM' }),
      agentDid: TEST_AGENT_DID,
      expectedOrg: 'company.com',
    });
    expect(result.orgDomain).toBe('Company.COM'); // raw value preserved
  });

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

  test('throws WrongOrgError when credential has null orgDomain', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: null }),
        agentDid: TEST_AGENT_DID,
        expectedOrg: 'company.com',
      }),
    ).rejects.toBeInstanceOf(WrongOrgError);
  });

  test('WrongOrgError has code WRONG_ORG and correct details', async () => {
    const verifier = await makeVerifier();
    let err: WrongOrgError | undefined;
    try {
      await verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: 'wrong.com' }),
        agentDid: TEST_AGENT_DID,
        expectedOrg: 'company.com',
      });
    } catch (e) {
      err = e as WrongOrgError;
    }

    expect(err).toBeDefined();
    expect(err!.code).toBe('WRONG_ORG');
    expect(err!.details?.['expectedOrg']).toBe('company.com');
    expect(err!.details?.['actualOrg']).toBe('wrong.com');
    expect(err!.details?.['issuerDid']).toBe(TEST_ISSUER_DID);
  });

  test('treats empty string orgDomain as null for comparison', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: '' }),
        agentDid: TEST_AGENT_DID,
        expectedOrg: 'company.com',
      }),
    ).rejects.toBeInstanceOf(WrongOrgError);
  });

  test('trims whitespace from expectedOrg before comparison (ops footgun guard)', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ orgDomain: 'company.com' }),
      agentDid: TEST_AGENT_DID,
      expectedOrg: '  company.com  ', // leading + trailing whitespace
    });
    expect(result.orgDomain).toBe('company.com');
  });

  test('throws TypeError for whitespace-only expectedOrg', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: 'company.com' }),
        agentDid: TEST_AGENT_DID,
        expectedOrg: '   ',
      }),
    ).rejects.toBeInstanceOf(TypeError);
  });
});

// ─── Layer 2c: Capability check ──────────────────────────────────────────────

describe('AgentVerifier — Layer 2c: capability check', () => {
  const TEST_CAPS: CapabilitySet = [
    { action: 'jira:read', scope: 'project/PROJ' },
    { action: 'github:read' }, // no scope = any resource
  ];

  async function makeVerifier(): Promise<AgentVerifier> {
    const store = await makeTrustStore();
    return createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
  }

  test('skips capability check when action is not provided', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
      agentDid: TEST_AGENT_DID,
    });
    expect(result.capabilities).toEqual(TEST_CAPS);
  });

  test('passes when action is in the capability set (with matching scope)', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
      agentDid: TEST_AGENT_DID,
      action: 'jira:read',
      scope: 'project/PROJ',
    });
    expect(result.subjectDid).toBe(TEST_AGENT_DID);
  });

  test('passes when action is in the set with no scope (grants any resource)', async () => {
    const verifier = await makeVerifier();
    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
      agentDid: TEST_AGENT_DID,
      action: 'github:read',
      scope: 'repo/agents',
    });
    expect(result.subjectDid).toBe(TEST_AGENT_DID);
  });

  test('throws AgentUnauthorizedError when action is not in capability set', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:write',
        scope: 'project/PROJ',
      }),
    ).rejects.toBeInstanceOf(AgentUnauthorizedError);
  });

  test('throws AgentUnauthorizedError when scope does not match', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:read',
        scope: 'project/OTHER', // PROJ is granted, not OTHER
      }),
    ).rejects.toBeInstanceOf(AgentUnauthorizedError);
  });

  test('throws AgentUnauthorizedError when capability set is empty', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: [] }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:read',
      }),
    ).rejects.toBeInstanceOf(AgentUnauthorizedError);
  });

  test('throws AgentUnauthorizedError when credential has no capabilities field', async () => {
    const verifier = await makeVerifier();
    // makeBindingJwt with no capabilities → capabilities not in credential subject
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({}), // no capabilities key
        agentDid: TEST_AGENT_DID,
        action: 'jira:read',
      }),
    ).rejects.toBeInstanceOf(AgentUnauthorizedError);
  });

  test('CapabilityParseError propagates when action is malformed', async () => {
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
        agentDid: TEST_AGENT_DID,
        action: '', // empty action is a caller bug → CapabilityParseError
      }),
    ).rejects.toBeInstanceOf(CapabilityParseError);
  });

  test('CapabilitySetTooLargeError propagates when credential has oversized capability set', async () => {
    const oversizedCaps: CapabilitySet = Array.from(
      { length: MAX_CAPABILITY_SET_SIZE + 1 },
      (_, i) => ({ action: `cap:action${i}` }),
    );
    const verifier = await makeVerifier();
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: oversizedCaps }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:read',
      }),
    ).rejects.toBeInstanceOf(CapabilitySetTooLargeError);
  });

  test('AgentUnauthorizedError has code UNAUTHORIZED and details', async () => {
    const verifier = await makeVerifier();
    let err: AgentUnauthorizedError | undefined;
    try {
      await verifier.verify({
        bindingJwt: makeBindingJwt({ capabilities: TEST_CAPS }),
        agentDid: TEST_AGENT_DID,
        action: 'jira:write',
        scope: 'project/PROJ',
      });
    } catch (e) {
      err = e as AgentUnauthorizedError;
    }

    expect(err).toBeDefined();
    expect(err!.code).toBe('UNAUTHORIZED');
    expect(err!.details?.['action']).toBe('jira:write');
    expect(err!.details?.['scope']).toBe('project/PROJ');
    expect(err!.details?.['subjectDid']).toBe(TEST_AGENT_DID);
  });
});

// ─── Full happy path ──────────────────────────────────────────────────────────

describe('AgentVerifier — full happy path', () => {
  test('all four checks pass — returns complete result', async () => {
    const caps: CapabilitySet = [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'slack:post' },
    ];

    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    const result: AgentVerifyResult = await verifier.verify({
      bindingJwt: makeBindingJwt({ orgDomain: 'company.com', capabilities: caps }),
      agentDid: TEST_AGENT_DID,
      expectedOrg: 'company.com',
      action: 'jira:read',
      scope: 'project/PROJ',
    });

    expect(result.issuerDid).toBe(TEST_ISSUER_DID);
    expect(result.subjectDid).toBe(TEST_AGENT_DID);
    expect(result.orgDomain).toBe('company.com');
    expect(result.capabilities).toEqual(caps);
    expect(result.credential).toBeDefined();
    expect(result.credential.issuer).toBe(TEST_ISSUER_DID);
  });

  test('result has correct shape without optional checks', async () => {
    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });

    const result = await verifier.verify({
      bindingJwt: makeBindingJwt({ orgDomain: 'company.com' }),
      agentDid: TEST_AGENT_DID,
    });

    expect(result.issuerDid).toBe(TEST_ISSUER_DID);
    expect(result.subjectDid).toBe(TEST_AGENT_DID);
    expect(result.orgDomain).toBe('company.com');
    expect(result.capabilities).toEqual([]); // no capabilities in JWT
    expect(result.credential).toBeDefined();
  });
});

// ─── Input validation guards ──────────────────────────────────────────────────

describe('AgentVerifier — input validation', () => {
  test('throws TypeError for empty-string agentDid (empty string bypasses TypeScript type)', async () => {
    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt({ orgDomain: 'company.com' }),
        agentDid: '',
      }),
    ).rejects.toBeInstanceOf(TypeError);
  });
});

// ─── Factory ──────────────────────────────────────────────────────────────────

describe('AgentVerifier — createAgentVerifier factory', () => {
  test('returns an AgentVerifier instance', async () => {
    const store = await makeTrustStore();
    const verifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
    expect(verifier).toBeInstanceOf(AgentVerifier);
  });

  test('satisfies AgentVerifier interface (verify method exists)', async () => {
    const store = await makeTrustStore();
    const verifier: AgentVerifier = createAgentVerifier({
      vcVerifier: mockVcVerifier(validVcResult()),
      trustAnchorStore: store,
    });
    expect(typeof verifier.verify).toBe('function');
  });
});
