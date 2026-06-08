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
} from '#index.js';
import type { IssueCredentialOptions } from '#index.js';
import { issueDelegatedCredential } from '#auth/index.js';
import { issueCredentialWithSdk } from '#auth/credential-issuance.js';
import { issueCredentialBodySchema } from '#transport/validation.js';
import { createSigningSdk } from './mocks/index.js';

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

describe('a generous ceiling never unlocks a second delegation hop', () => {
  // The platform permits exactly one delegation event: human -> agent -> worker. The
  // worker cannot re-delegate. maxDepth is a backstop, not the primary invariant -- the
  // source-type guard blocks re-delegation regardless of how high the ceiling is, so
  // every ceiling >= 2 behaves identically (one hop) and only maxDepth: 1 blocks the
  // first hop. There is no legitimate path that produces a chain deeper than one hop.
  function delegate(
    delegator: ReturnType<typeof generateDidKey>,
    target: ReturnType<typeof generateDidKey>,
    source: string,
  ): Promise<string> {
    return issueDelegatedCredential(
      delegator.did,
      createSigner(delegator.privateKey),
      source,
      decodeJwt(source).payload.jti as string,
      { columns: [...SCOPE.columns], actions: [...SCOPE.actions] },
      {
        targetAgent: target.did,
        columns: [...SCOPE.columns],
        actions: [...SCOPE.actions],
        expiresIn: '1h',
      },
    );
  }

  it('issues one hop under maxDepth: 3 then refuses to re-delegate the result', async () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();
    const subWorker = generateDidKey();

    const root = await issueRoot(human, supervisor.did, 3);
    const workerCred = await delegate(supervisor, worker, root);
    expect(decodeJwt(workerCred).payload.maxDepth).toBe(3);

    await expect(delegate(worker, subWorker, workerCred)).rejects.toThrow(
      /re-delegation is not permitted/i,
    );
  });

  it('treats maxDepth: 2 and maxDepth: 5 identically -- each allows exactly one hop', async () => {
    const human = generateDidKey();
    const supervisor = generateDidKey();
    const worker = generateDidKey();

    for (const ceiling of [2, 5]) {
      const root = await issueRoot(human, supervisor.did, ceiling);
      const delegated = await delegate(supervisor, worker, root);
      expect(decodeJwt(delegated).payload.maxDepth).toBe(ceiling);
    }
  });
});

describe('issueCredentialWithSdk embeds maxDepth in the issued JWT', () => {
  it('forwards explicit maxDepth into the credential', async () => {
    const human = generateDidKey();
    const agent = generateDidKey();
    const sdk = createSigningSdk(human);
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
    const sdk = createSigningSdk(human);
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
    const sdk = createSigningSdk(human);
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
  let liveCache: { set(token: string, session: never, opts: { portable: boolean }): void };
  let tokenCounter = 0;

  // Each test registers its own session under a unique token so its captured
  // options live in a test-local closure, never shared across tests. This keeps
  // the block correct under concurrent/sharded execution, not just serial.
  function registerCapturingSession() {
    let captured: IssueCredentialOptions | undefined;
    tokenCounter += 1;
    const token = `test-session-token-${tokenCounter}`;
    const mockSession = {
      humanDid: 'did:key:zTestHuman',
      email: 'test@test.com',
      scopeCeiling: { columns: ['*'], actions: ['read'], source: 'test', resolvedFrom: 'test' },
      async issueCredential(options: IssueCredentialOptions) {
        captured = options;
        const human = generateDidKey();
        return issueCredential(human.did, human.privateKey, options);
      },
      async revokeCredential() { return {}; },
    };
    liveCache.set(token, mockSession as never, { portable: false });
    return { token, getCaptured: () => captured };
  }

  async function startTestServer() {
    const { createServerApp } = await import('../packages/server/src/app.js');
    const { loadServerConfig } = await import('../packages/server/src/config.js');
    const { mountRestRoutes } = await import('../packages/server/src/routes.js');
    const { createOidcServices } = await import('../packages/server/src/oidc.js');
    const { createPerSessionRateLimiter } = await import('../packages/server/src/rate-limit.js');
    const { SessionManager, LiveSessionCache } = await import('../packages/server/src/session.js');

    const config = loadServerConfig({ NODE_ENV: 'test' });
    const app = createServerApp(config);

    liveCache = new LiveSessionCache(config.sessionTtlMs);

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
    const { token, getCaptured } = registerCapturingSession();

    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': token },
      body: JSON.stringify({
        agent: 'did:key:z6MkAgent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
        maxDepth: 1,
      }),
    });

    expect(res.status).toBe(200);
    const captured = getCaptured();
    expect(captured).toBeDefined();
    expect(captured!.maxDepth).toBe(1);

    const body = await res.json() as { credential: string };
    const decoded = decodeJwt(body.credential);
    expect(decoded.payload.maxDepth).toBe(1);
  });

  it('omits maxDepth from issueCredential when not in the HTTP body', async () => {
    const { token, getCaptured } = registerCapturingSession();

    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': token },
      body: JSON.stringify({
        agent: 'did:key:z6MkAgent',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '4h',
      }),
    });

    expect(res.status).toBe(200);
    const captured = getCaptured();
    expect(captured).toBeDefined();
    expect(captured!.maxDepth).toBeUndefined();

    const body = await res.json() as { credential: string };
    const decoded = decodeJwt(body.credential);
    expect(decoded.payload.maxDepth).toBe(2);
  });

  it('returns 400 when maxDepth is 0', async () => {
    const { token } = registerCapturingSession();

    const res = await fetch(`${baseUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-session': token },
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
