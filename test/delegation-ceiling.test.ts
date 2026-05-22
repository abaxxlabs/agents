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

import { describe, it, expect, afterAll, beforeAll } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import {
  generateDidKey,
  createSigner,
  createJwt,
  issueCredential,
  decodeJwt,
} from '../src/index.js';
import type { IssueCredentialOptions } from '../src/index.js';
import { issueDelegatedCredential } from '../src/auth/index.js';
import { issueCredentialWithSdk } from '../src/auth/credential-issuance.js';
import type { IdSdkInstance } from '../src/types/id-sdk.js';
import { issueCredentialBodySchema } from '../src/transport/validation.js';

const SCOPE = { columns: ['patients.name'], actions: ['read'] as const };

async function issueRoot(
  human: ReturnType<typeof generateDidKey>,
  subject: string,
  maxDepth?: number,
): Promise<string> {
  return issueCredential(human.did, human.privateKey, {
    agent: subject,
    columns: [...SCOPE.columns],
    actions: [...SCOPE.actions],
    expiresIn: '4h',
    ...(maxDepth !== undefined ? { maxDepth } : {}),
  });
}

describe('issueCredential embeds maxDepth in the issued JWT', () => {
  it('writes the provided maxDepth top-level', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const jwt = await issueRoot(human, agent.did, 3);
    const decoded = decodeJwt(jwt);
    expect(decoded.payload.maxDepth).toBe(3);
  });

  it('defaults to the library ceiling of 2 when omitted', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const jwt = await issueRoot(human, agent.did);
    const decoded = decodeJwt(jwt);
    expect(decoded.payload.maxDepth).toBe(2);
  });

  it('rejects non-positive integer ceilings at issuance', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    await expect(
      issueCredential(human.did, human.privateKey, {
        agent: agent.did,
        columns: [...SCOPE.columns],
        actions: [...SCOPE.actions],
        expiresIn: '4h',
        maxDepth: 0,
      }),
    ).rejects.toThrow(/positive integer/);
  });
});

describe('issueDelegatedCredential inherits parent ceiling, never widens', () => {
  it('embeds the parent ceiling unchanged in the delegated credential', async () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();
    const root = await issueRoot(human, supervisor.did, 3);
    const rootJti = decodeJwt(root).payload.jti as string;

    const delegated = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      root,
      rootJti,
      { columns: [...SCOPE.columns], actions: [...SCOPE.actions] },
      {
        targetAgent: worker.did,
        columns: [...SCOPE.columns],
        actions: [...SCOPE.actions],
        expiresIn: '1h',
      },
    );

    expect(decodeJwt(delegated).payload.maxDepth).toBe(3);
  });

  it('treats a legacy root credential without maxDepth as the library default', async () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();

    const now = Math.floor(Date.now() / 1000);
    const legacyRoot = await createJwt(
      {
        iss: human.did,
        sub: supervisor.did,
        jti: 'legacy-root',
        iat: now,
        exp: now + 3600,
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'AgentScopeCredential'],
          credentialSubject: {
            id: supervisor.did,
            scope: { columns: [...SCOPE.columns], actions: [...SCOPE.actions] },
            owner: human.did,
          },
        },
      },
      human.privateKey,
    );

    const delegated = await issueDelegatedCredential(
      supervisor.did,
      createSigner(supervisor.privateKey),
      legacyRoot,
      'legacy-root',
      { columns: [...SCOPE.columns], actions: [...SCOPE.actions] },
      {
        targetAgent: worker.did,
        columns: [...SCOPE.columns],
        actions: [...SCOPE.actions],
        expiresIn: '1h',
      },
    );

    expect(decodeJwt(delegated).payload.maxDepth).toBe(2);
  });

  it('rejects the first hop when parent ceiling is 1', async () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();
    const root = await issueRoot(human, supervisor.did, 1);
    const rootJti = decodeJwt(root).payload.jti as string;

    await expect(
      issueDelegatedCredential(
        supervisor.did,
        createSigner(supervisor.privateKey),
        root,
        rootJti,
        { columns: [...SCOPE.columns], actions: [...SCOPE.actions] },
        {
          targetAgent: worker.did,
          columns: [...SCOPE.columns],
          actions: [...SCOPE.actions],
          expiresIn: '1h',
        },
      ),
    ).rejects.toThrow(/chain depth 1 exceeds maximum 1/);
  });
});

function createMockSdk(signingKey: ReturnType<typeof generateDidKey>): IdSdkInstance {
  let capturedData: Record<string, unknown> = {};
  return {
    vc: {
      createCredential: async (_issuer, _subject, data) => {
        capturedData = data as Record<string, unknown>;
        return data;
      },
      getSignerOptions: async (did, subjectDid) => ({
        kid: `${did}#key-1`,
        issuerDid: did,
        subjectDid,
        signer: createSigner(signingKey.privateKey).signJwt as never,
      }),
      signCredential: async (vc) => {
        const data = vc as Record<string, unknown>;
        const now = Math.floor(Date.now() / 1000);
        return createJwt(
          { iss: signingKey.did, sub: String(data.id), iat: now, exp: now + 3600, maxDepth: data.maxDepth },
          signingKey.privateKey,
        );
      },
      verifyJWT: async () => true,
      decodeJWT: async () => ({ header: {}, payload: {}, signature: '' }),
      parseJWT: async () => ({}),
      createRevocableCredential: async () => ({}),
      revokeCredential: async () => ({}),
      checkCredentialStatus: async () => ({ revoked: false, suspended: false }),
      EdDsaSigner: (pk: Uint8Array) => createSigner(pk).signJwt as never,
    },
    did: { resolve: async () => ({ didDocument: {}, didResolutionMetadata: {} }) },
    agent: {},
    connectedDid: signingKey.did,
  };
}

describe('issueCredentialWithSdk embeds maxDepth in the issued JWT', () => {
  it('forwards explicit maxDepth into the credential', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const sdk = createMockSdk(human);
    const jwt = await issueCredentialWithSdk(sdk, human.did, {
      agent: agent.did,
      columns: [...SCOPE.columns],
      actions: [...SCOPE.actions],
      expiresIn: '4h',
      maxDepth: 1,
    });
    expect(decodeJwt(jwt).payload.maxDepth).toBe(1);
  });

  it('defaults to library ceiling of 2 when maxDepth is omitted', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const sdk = createMockSdk(human);
    const jwt = await issueCredentialWithSdk(sdk, human.did, {
      agent: agent.did,
      columns: [...SCOPE.columns],
      actions: [...SCOPE.actions],
      expiresIn: '4h',
    });
    expect(decodeJwt(jwt).payload.maxDepth).toBe(2);
  });

  it('rejects non-positive integer maxDepth', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const sdk = createMockSdk(human);
    await expect(
      issueCredentialWithSdk(sdk, human.did, {
        agent: agent.did,
        columns: [...SCOPE.columns],
        actions: [...SCOPE.actions],
        expiresIn: '4h',
        maxDepth: 0,
      }),
    ).rejects.toThrow(/positive integer/);
  });
});

describe('issueCredentialBodySchema validates maxDepth from REST/MCP callers', () => {
  const validBody = {
    agent: 'did:key:z6MkTest',
    columns: ['patients.name'],
    actions: ['read'] as const,
    expiresIn: '4h',
  };

  it('accepts a valid positive integer', () => {
    const result = issueCredentialBodySchema.safeParse({ ...validBody, maxDepth: 1 });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.maxDepth).toBe(1);
  });

  it('passes through when omitted (undefined)', () => {
    const result = issueCredentialBodySchema.safeParse(validBody);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.maxDepth).toBeUndefined();
  });

  it('rejects zero', () => {
    const result = issueCredentialBodySchema.safeParse({ ...validBody, maxDepth: 0 });
    expect(result.success).toBe(false);
  });

  it('rejects negative values', () => {
    const result = issueCredentialBodySchema.safeParse({ ...validBody, maxDepth: -1 });
    expect(result.success).toBe(false);
  });

  it('rejects non-integer values', () => {
    const result = issueCredentialBodySchema.safeParse({ ...validBody, maxDepth: 1.5 });
    expect(result.success).toBe(false);
  });

  it('round-trips through issueCredential with maxDepth:1', async () => {
    const parsed = issueCredentialBodySchema.parse({ ...validBody, maxDepth: 1 });
    const human = generateDidKey();
    const agent = generateDidKey();
    const jwt = await issueCredential(human.did, human.privateKey, {
      agent: agent.did,
      columns: parsed.columns,
      actions: parsed.actions,
      expiresIn: parsed.expiresIn,
      maxDepth: parsed.maxDepth,
    });
    expect(decodeJwt(jwt).payload.maxDepth).toBe(1);
  });
});

describe('POST /credentials threads maxDepth through the HTTP route handler', () => {
  let server: Server;
  let baseUrl: string;
  const sessionToken = 'test-session-token';
  let capturedOptions: IssueCredentialOptions | undefined;

  async function startTestServer() {
    const { createServerApp } = await import('../packages/server/src/app.js');
    const { loadServerConfig } = await import('../packages/server/src/config.js');
    const { mountRestRoutes } = await import('../packages/server/src/routes.js');
    const { createOidcServices } = await import('../packages/server/src/oidc.js');
    const { createPerSessionRateLimiter } = await import('../packages/server/src/rate-limit.js');
    const { SessionManager, LiveSessionCache } = await import('../packages/server/src/session.js');

    const config = loadServerConfig({ NODE_ENV: 'test' });
    const app = createServerApp(config);

    const mockSession = {
      humanDid: 'did:key:zTestHuman',
      email: 'test@test.com',
      scopeCeiling: { columns: ['*'], actions: ['read'], source: 'test', resolvedFrom: 'test' },
      async issueCredential(options: IssueCredentialOptions) {
        capturedOptions = options;
        const human = generateDidKey();
        return issueCredential(human.did, human.privateKey, options);
      },
      async revokeCredential() { return {}; },
    };

    const liveCache = new LiveSessionCache(config.sessionTtlMs);
    liveCache.set(sessionToken, mockSession as never, { portable: false });

    const fakeScope = {
      verifierDid: 'did:key:zTestServer',
      credentialMaxTtlMs: 86_400_000,
      getServerStatus: async () => ({
        agentCount: 0, auditRecordCount: 0, encryptedColumns: [],
        inMemoryAgents: 0, scopeMode: 'projection' as const,
      }),
    };

    const sessionManager = new SessionManager({
      config,
      scopeProvider: () => fakeScope as never,
      liveCache: liveCache as never,
    });

    mountRestRoutes(app, {
      config,
      scope: fakeScope as never,
      sessionManager,
      oidc: createOidcServices(config),
      rateLimiter: createPerSessionRateLimiter(),
      getReadinessChecks: () => [],
    });

    return new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const port = (server.address() as AddressInfo).port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  }

  beforeAll(() => startTestServer());
  afterAll(() => { server?.close(); });

  it('passes maxDepth:1 from the HTTP body to issueCredential', async () => {
    capturedOptions = undefined;

    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': sessionToken },
      body: JSON.stringify({
        agent: 'did:key:z6MkAgent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
        maxDepth: 1,
      }),
    });

    expect(res.status).toBe(200);
    expect(capturedOptions).toBeDefined();
    expect(capturedOptions!.maxDepth).toBe(1);

    const body = await res.json() as { credential: string };
    const decoded = decodeJwt(body.credential);
    expect(decoded.payload.maxDepth).toBe(1);
  });

  it('omits maxDepth from issueCredential when not in the HTTP body', async () => {
    capturedOptions = undefined;

    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': sessionToken },
      body: JSON.stringify({
        agent: 'did:key:z6MkAgent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      }),
    });

    expect(res.status).toBe(200);
    expect(capturedOptions).toBeDefined();
    expect(capturedOptions!.maxDepth).toBeUndefined();

    const body = await res.json() as { credential: string };
    const decoded = decodeJwt(body.credential);
    expect(decoded.payload.maxDepth).toBe(2);
  });

  it('returns 400 when maxDepth is 0', async () => {
    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': sessionToken },
      body: JSON.stringify({
        agent: 'did:key:z6MkAgent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
        maxDepth: 0,
      }),
    });

    expect(res.status).toBe(400);
  });
});
