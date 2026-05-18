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

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LocalTrustAnchorStore } from '../src/discovery/trust-anchor.js';
import { issueCredentialFromParent, createSessionFromDid } from '../src/auth/agent.js';
import { VcVerifier } from '../src/vc-verifier.js';
import { InMemoryRevocationStore } from '../src/storage/memory/revocation-store.js';
import { AgentVerifier, ParentScopeExceededError } from '../src/identity/agent-verifier.js';
import { CapabilityEngine } from '../src/capability/engine.js';
import { AuditLogger } from '../src/audit-logger.js';
import { generateDidKey, createSigner } from '../src/auth/index.js';
import { ParentCredentialRequestFailedError } from '../src/errors.js';
import type { AuditEntry } from '../src/types.js';
import type { CapabilitySet } from '../src/capability/types.js';
import type { AuditStore } from '../src/storage/types.js';

/** Mock AuditStore for audit logger tests. */
function createTestAuditStore(): AuditStore {
  return {
    append: vi.fn().mockResolvedValue(undefined),
    loadLastRecord: vi.fn().mockResolvedValue(null),
    loadLastRecordLocked: vi.fn().mockResolvedValue(null),
    query: vi.fn().mockResolvedValue([]),
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const OWN_DID = 'did:key:z6MkownServerTest123';
const PARENT_DID = 'did:dht:parentOrgInstance456';
const AGENT_DID = 'did:key:z6MkagentTest789';
const ISSUER_DID = 'did:key:z6MkTestIssuer1234567890';

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

describe('addParentTrust', () => {
  it('adds a parent trust anchor with source "parent"', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addParentTrust(PARENT_DID);

    expect(store.isTrusted(PARENT_DID)).toBe(true);
    const anchor = store.list().find((a) => a.did === PARENT_DID);
    expect(anchor?.source).toBe('parent');
    expect(anchor?.label).toBe('parent-instance');
  });

  it('does not overwrite an existing env anchor', async () => {
    const store = new LocalTrustAnchorStore({
      ownServerDid: OWN_DID,
      initialTrustedServers: [PARENT_DID],
    });
    expect(store.list().find((a) => a.did === PARENT_DID)?.source).toBe('env');

    await store.addParentTrust(PARENT_DID);

    const anchor = store.list().find((a) => a.did === PARENT_DID);
    expect(anchor?.source).toBe('env');
  });

  it('does not overwrite an existing api anchor', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await store.addTrustedServer(PARENT_DID, 'api', 'federation-peer');

    expect(store.list().find((a) => a.did === PARENT_DID)?.source).toBe('api');

    await store.addParentTrust(PARENT_DID);

    const anchor = store.list().find((a) => a.did === PARENT_DID);
    expect(anchor?.source).toBe('api');
  });

  it('does not overwrite an existing local anchor', async () => {
    const localDid = 'did:key:z6MklocalServerDid999';
    const store = new LocalTrustAnchorStore({ ownServerDid: localDid });
    expect(store.list().find((a) => a.did === localDid)?.source).toBe('local');

    await store.addParentTrust(localDid);

    const anchor = store.list().find((a) => a.did === localDid);
    expect(anchor?.source).toBe('local');
  });

  it('rejects non-did:key/did:dht methods', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.addParentTrust('did:web:example.com')).rejects.toThrow(TypeError);
  });

  it('rejects empty string', async () => {
    const store = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await expect(store.addParentTrust('')).rejects.toThrow(TypeError);
  });
});

describe('issueCredentialFromParent', () => {
  it('delegates to provider.requestAgentCredential', async () => {
    const expected = { jwt: 'eyJ...parent', issuerDid: PARENT_DID };
    const provider = makeParentProvider(expected);

    const result = await issueCredentialFromParent(provider, 'access-token-123', AGENT_DID, {
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    expect(result).toEqual(expected);
    expect(provider.requestAgentCredential).toHaveBeenCalledWith('access-token-123', AGENT_DID, {
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });
  });
});

describe('createSessionFromDid — parent credential fallback', () => {
  const humanKeys = generateDidKey();

  it('catches ParentCredentialRequestFailedError and falls through to local signing', async () => {
    const provider = makeFailingProvider(
      new ParentCredentialRequestFailedError(PARENT_DID, 'network timeout'),
    );

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
    );

    const jwt = await session.issueCredential({
      agent: AGENT_DID,
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    expect(jwt).toBeDefined();
    expect(jwt.split('.')).toHaveLength(3);
  });

  it('re-throws non-ParentCredentialRequestFailedError errors', async () => {
    const provider = makeFailingProvider(new TypeError('null pointer in JWT parsing'));

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
    );

    await expect(
      session.issueCredential({
        agent: AGENT_DID,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      }),
    ).rejects.toThrow(TypeError);
  });

  it('stores parentIssuerDid and parentCredentialExp on session', () => {
    const exp = Math.floor(Date.now() / 1000) + 7200;
    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier,
      undefined,
      undefined,
      humanKeys.privateKey,
      undefined,
      {
        provider: makeParentProvider({ jwt: 'x', issuerDid: PARENT_DID }),
        accessToken: 'tok',
        issuerDid: PARENT_DID,
        credentialExp: exp,
      },
    );

    expect(session.parentIssuerDid).toBe(PARENT_DID);
    expect(session.parentCredentialExp).toBe(exp);
  });

  it('rejects issueCredential when parent credential has expired', async () => {
    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier,
      undefined,
      undefined,
      humanKeys.privateKey,
      undefined,
      {
        provider: makeParentProvider({ jwt: 'x', issuerDid: PARENT_DID }),
        accessToken: 'tok',
        issuerDid: PARENT_DID,
        credentialExp: Math.floor(Date.now() / 1000) - 100,
      },
    );

    await expect(
      session.issueCredential({
        agent: AGENT_DID,
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      }),
    ).rejects.toThrow('Parent credential has expired');
  });
});

describe('createSessionFromDid — requireParent', () => {
  const humanKeys = generateDidKey();

  it('throws when parent provider fails and requireParent is set', async () => {
    const provider = makeFailingProvider(
      new ParentCredentialRequestFailedError(PARENT_DID, 'network timeout'),
    );

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      {} as unknown as VcVerifier, // verifier — not exercised in this path
      undefined, // sdk
      undefined, // oidcConfig
      humanKeys.privateKey,
      undefined, // ceiling
      {
        provider,
        accessToken: 'token-123',
        issuerDid: PARENT_DID,
        credentialExp: Math.floor(Date.now() / 1000) + 3600,
      },
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
  it('writes locally first, returns empty result when no SDK (no throw)', async () => {
    const humanKeys = generateDidKey();
    const realVerifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      realVerifier,
      undefined, // no SDK
      undefined, // no oidcConfig
      humanKeys.privateKey,
    );

    const jti = 'revoke-local-only-jti-d6';
    const result = await session.revokeCredential(jti);

    // Local write succeeded, no SDK notification attempted.
    expect(result.sdkNotificationFailed).toBeUndefined();
    // Revocation is durable in the local store.
    expect(await realVerifier.revocationStore.isRevoked(jti)).toBe(true);
  });

  it('SDK failure does not fail local revocation — sdkNotificationFailed is set', async () => {
    const humanKeys = generateDidKey();
    const realVerifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });

    const failingSdk = {
      vc: {
        revokeCredential: vi.fn().mockRejectedValue(new Error('SDK network failure')),
      },
    } as unknown as Parameters<typeof createSessionFromDid>[3];

    const session = createSessionFromDid(
      humanKeys.did,
      'test@example.com',
      realVerifier,
      failingSdk,
      undefined,
      humanKeys.privateKey,
    );

    const jti = 'revoke-sdk-fail-jti-d6';
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const result = await session.revokeCredential(jti);
      // SDK failure does not fail the revocation.
      expect(result.sdkNotificationFailed).toBeInstanceOf(Error);
      expect(result.sdkNotificationFailed?.message).toContain('SDK network failure');
      // Local revocation succeeded despite SDK failure.
      expect(await realVerifier.revocationStore.isRevoked(jti)).toBe(true);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('store write failure propagates as hard failure (no silent continue)', async () => {
    const humanKeys = generateDidKey();

    // Inject a failing revocation store.
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

describe('CapabilityEngine.isSubsetOf — ceiling enforcement', () => {
  const engine = new CapabilityEngine();

  it('child subset of parent returns true', () => {
    const child: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];
    const parent: CapabilitySet = [
      { resource: 'data:patients', action: 'read' },
      { resource: 'data:billing', action: 'read' },
    ];
    expect(engine.isSubsetOf(child, parent)).toBe(true);
  });

  it('child exceeding parent returns false', () => {
    const child: CapabilitySet = [
      { resource: 'data:patients', action: 'read' },
      { resource: 'data:secrets', action: 'write' },
    ];
    const parent: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];
    expect(engine.isSubsetOf(child, parent)).toBe(false);
  });

  it('empty child is always a subset (vacuous truth)', () => {
    const parent: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];
    expect(engine.isSubsetOf([], parent)).toBe(true);
  });

  it('empty child is a subset of empty parent', () => {
    expect(engine.isSubsetOf([], [])).toBe(true);
  });
});

describe('AgentVerifier — Step 2.5 parentScopeCeiling', () => {
  async function makeVerifier() {
    const trustStore = new LocalTrustAnchorStore({ ownServerDid: OWN_DID });
    await trustStore.addTrustedServer(ISSUER_DID, 'api');

    const mockVcVerifier = {
      verify: async () => ({
        valid: true,
        status: 'VALID' as const,
        credential: {
          issuer: ISSUER_DID,
          subject: AGENT_DID,
          issuedAt: new Date(Date.now() - 60_000),
          expiresAt: new Date(Date.now() + 3600_000),
        },
      }),
    } as unknown as VcVerifier;

    return new AgentVerifier({
      vcVerifier: mockVcVerifier,
      trustAnchorStore: trustStore,
      capabilityEngine: new CapabilityEngine(),
    });
  }

  it('passes when capabilities are within ceiling', async () => {
    const verifier = await makeVerifier();
    const caps: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];
    const ceiling: CapabilitySet = [
      { resource: 'data:patients', action: 'read' },
      { resource: 'data:billing', action: 'read' },
    ];

    const result = await verifier.verify({
      bindingJwt: makeBindingJwt(caps),
      agentDid: AGENT_DID,
      parentScopeCeiling: ceiling,
    });

    expect(result.issuerDid).toBe(ISSUER_DID);
  });

  it('throws ParentScopeExceededError when capabilities exceed ceiling', async () => {
    const verifier = await makeVerifier();
    const caps: CapabilitySet = [
      { resource: 'data:patients', action: 'read' },
      { resource: 'data:secrets', action: 'write' },
    ];
    const ceiling: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];

    await expect(
      verifier.verify({
        bindingJwt: makeBindingJwt(caps),
        agentDid: AGENT_DID,
        parentScopeCeiling: ceiling,
      }),
    ).rejects.toThrow(ParentScopeExceededError);
  });

  it('empty capabilities pass ceiling check (vacuous truth)', async () => {
    const verifier = await makeVerifier();
    const ceiling: CapabilitySet = [{ resource: 'data:patients', action: 'read' }];

    const result = await verifier.verify({
      bindingJwt: makeBindingJwt([]),
      agentDid: AGENT_DID,
      parentScopeCeiling: ceiling,
    });

    expect(result.issuerDid).toBe(ISSUER_DID);
  });
});

describe('Audit Logger — V3 orgId records', () => {
  let agent: ReturnType<typeof generateDidKey>;
  let human: ReturnType<typeof generateDidKey>;

  beforeEach(() => {
    agent = generateDidKey();
    human = generateDidKey();
  });

  it('version is 3 when orgId is present', async () => {
    const logger = new AuditLogger({
      auditStore: createTestAuditStore(),
      enabled: true,
    });

    const entry: AuditEntry = {
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ...',
      sql: 'SELECT * FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 10,
      orgId: PARENT_DID,
    };

    const record = await logger.log(entry, createSigner(agent.privateKey));
    expect(record.version).toBe(3);
    expect(record.orgId).toBe(PARENT_DID);
  });

  it('version is 3 even when orgId is absent', async () => {
    const logger = new AuditLogger({
      auditStore: createTestAuditStore(),
      enabled: true,
    });

    const entry: AuditEntry = {
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ...',
      sql: 'SELECT * FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 10,
    };

    const record = await logger.log(entry, createSigner(agent.privateKey));
    expect(record.version).toBe(3);
    expect(record.orgId).toBeUndefined();
  });

  it('orgId is persisted via auditStore.append', async () => {
    const store = createTestAuditStore();
    const logger = new AuditLogger({ auditStore: store, enabled: true });

    const entry: AuditEntry = {
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ...',
      sql: 'SELECT * FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 10,
      orgId: PARENT_DID,
    };

    await logger.log(entry, createSigner(agent.privateKey));

    expect(store.append).toHaveBeenCalledTimes(1);
    const appendedRecord = (store.append as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(appendedRecord.orgId).toBe(PARENT_DID);
  });

  it('empty string orgId is preserved on record (signAuditRecord !== undefined check)', async () => {
    const logger = new AuditLogger({
      auditStore: createTestAuditStore(),
      enabled: true,
    });

    const entry: AuditEntry = {
      agentDid: agent.did,
      ownerDid: human.did,
      credentialJwt: 'eyJ...',
      sql: 'SELECT * FROM patients',
      columnsAccessed: ['patients.name'],
      rowCount: 1,
      durationMs: 10,
      orgId: '',
    };

    const record = await logger.log(entry, createSigner(agent.privateKey));
    expect(record.orgId).toBe('');
  });
});
