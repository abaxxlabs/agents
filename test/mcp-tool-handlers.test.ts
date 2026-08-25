import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerTools, type ToolDependencies } from '#mcp/tools.js';
import type { ChallengeStore } from '#mcp/challenge-store.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import type { TrustAnchorStore } from '#discovery/trust-anchor.js';
import type { RateLimiter } from '#transport/rate-limit.js';
import type { Logger } from '#observability/logger.js';
import {
  createAgentToolServiceFakes,
  createMcpSession,
  createMockMcpServer,
  getRegisteredMcpTool,
  parseMcpToolPayload,
} from './mocks/mcp.js';

function createIdentity() {
  const signJwt = vi.fn(async () => 'signed-jwt');
  const serverIdentity = {
    did: 'did:key:server',
    signer: { signJwt },
    publicKey: new Uint8Array(),
    isNew: false,
  } as ServerIdentity;
  const challengeResult = { challenge: 'challenge', expiresAt: 123, jti: 'jti-1' };
  const issue = vi.fn(() => challengeResult);
  const challengeStore = { issue } as unknown as ChallengeStore;
  const list = vi.fn(() => [{ did: 'did:key:trusted', source: 'local' }]);
  const trustAnchorStore = { list } as unknown as TrustAnchorStore;
  const check = vi.fn(() => ({
    allowed: true,
    limit: 100,
    remaining: 99,
    resetAt: Date.now() + 60_000,
  }));
  const rateLimiter = { check, sweep: vi.fn() } as RateLimiter;
  return {
    serverIdentity,
    signJwt,
    challengeStore,
    challengeResult,
    issue,
    trustAnchorStore,
    list,
    rateLimiter,
    check,
  };
}

describe('MCP tool handler contract', () => {
  let services: ReturnType<typeof createAgentToolServiceFakes>;
  let session: ReturnType<typeof createMcpSession>;
  let server: ReturnType<typeof createMockMcpServer>;
  let identity: ReturnType<typeof createIdentity>;
  let deps: ToolDependencies;
  let loggerError: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    services = createAgentToolServiceFakes();
    session = createMcpSession();
    server = createMockMcpServer();
    identity = createIdentity();
    loggerError = vi.fn();
    deps = {
      services,
      session,
      serverIdentity: identity.serverIdentity,
      trustAnchorStore: identity.trustAnchorStore,
      challengeStore: identity.challengeStore,
      rateLimiter: identity.rateLimiter,
      bindingVcJwt: 'binding-1',
      bindingExpiry: 100,
      orgDomain: 'example.com',
      logger: { error: loggerError } as unknown as Logger,
    };
    registerTools(server, deps);
  });

  it('delegates query with presentation and organization context', async () => {
    const result = await getRegisteredMcpTool(server, 'query').handler({
      agent: 'did:key:agent',
      credential: 'jwt',
      sql: 'SELECT id FROM patients',
      table: 'patients',
      params: [1],
    });

    expect(services.query.execute).toHaveBeenCalledWith(
      {
        agent: 'did:key:agent',
        credential: 'jwt',
        sql: 'SELECT id FROM patients',
        table: 'patients',
        params: [1],
        requirePresentation: true,
      },
      { orgId: 'did:key:org' },
    );
    expect(parseMcpToolPayload(result)).toMatchObject({ rows: [{ id: 1 }] });
  });

  it('preserves create-agent defaults, output shaping, and list limits', async () => {
    const created = await getRegisteredMcpTool(server, 'create-agent').handler({ name: 'worker' });
    const listed = await getRegisteredMcpTool(server, 'list-agents').handler({ limit: 250 });

    expect(services.agents.createAgent).toHaveBeenCalledWith({
      name: 'worker',
      ownerDid: 'did:key:human',
    });
    expect(parseMcpToolPayload(created)).toEqual({
      did: 'did:key:agent',
      name: 'worker',
      ownerDid: 'did:key:human',
      publicKey: 'AQID',
    });
    expect(services.agents.listAgents).toHaveBeenCalledWith({ ownerDid: undefined, limit: 100 });
    expect(parseMcpToolPayload(listed)).toEqual({ agents: [], count: 0 });
  });

  it('preserves credential defaults, session contexts, and response shaping', async () => {
    const issued = await getRegisteredMcpTool(server, 'issue-credential').handler({
      agent: 'did:key:agent',
      columns: ['patients.name'],
    });
    const revoked = await getRegisteredMcpTool(server, 'revoke-credential').handler({
      credentialId: 'credential-1',
    });
    const delegated = await getRegisteredMcpTool(server, 'delegate-credential').handler({
      sourceAgentDid: 'did:key:source',
      sourceCredential: 'source-jwt',
      targetAgent: 'did:key:target',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    expect(services.credentials.issueCredential).toHaveBeenCalledWith({
      agent: 'did:key:agent',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '4h',
    });
    expect(parseMcpToolPayload(issued)).toEqual({ credential: 'issued-credential' });
    expect(services.credentials.revokeCredential).toHaveBeenCalledWith(
      { credentialId: 'credential-1' },
      { ownerDid: 'did:key:human' },
    );
    expect(parseMcpToolPayload(revoked)).toEqual({ revoked: true, credentialId: 'credential-1' });
    expect(services.credentials.delegateCredential).toHaveBeenCalledWith(
      {
        sourceAgentDid: 'did:key:source',
        sourceCredential: 'source-jwt',
        targetAgent: 'did:key:target',
        columns: ['patients.name'],
        actions: ['read'],
        expiresIn: '1h',
      },
      { scopeCeiling: session.scopeCeiling },
    );
    expect(parseMcpToolPayload(delegated)).toEqual({ credential: 'delegated-credential' });
  });

  it('preserves credential TTL bounds and maxDepth propagation', async () => {
    const boundedServer = createMockMcpServer();
    registerTools(boundedServer, {
      services,
      session,
      credentialMaxTtlMs: 60 * 60 * 1000,
    });

    const rejectedIssue = await getRegisteredMcpTool(boundedServer, 'issue-credential').handler({
      agent: 'did:key:agent',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '2h',
    });
    const acceptedIssue = await getRegisteredMcpTool(boundedServer, 'issue-credential').handler({
      agent: 'did:key:agent',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '30m',
      maxDepth: 1,
    });
    const rejectedDelegate = await getRegisteredMcpTool(
      boundedServer,
      'delegate-credential',
    ).handler({
      sourceAgentDid: 'did:key:source',
      sourceCredential: 'source-jwt',
      targetAgent: 'did:key:target',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '2h',
    });

    expect(rejectedIssue).toMatchObject({ isError: true });
    expect(rejectedDelegate).toMatchObject({ isError: true });
    expect(parseMcpToolPayload(acceptedIssue)).toEqual({ credential: 'issued-credential' });
    expect(services.credentials.issueCredential).toHaveBeenCalledTimes(1);
    expect(services.credentials.issueCredential).toHaveBeenCalledWith({
      agent: 'did:key:agent',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '30m',
      maxDepth: 1,
    });
    expect(services.credentials.delegateCredential).not.toHaveBeenCalled();
  });

  it('preserves audit verification, export defaults, and chain context', async () => {
    const verified = await getRegisteredMcpTool(server, 'verify-audit').handler({
      auditId: 'audit-1',
    });
    const exported = await getRegisteredMcpTool(server, 'export-audit').handler({});
    await getRegisteredMcpTool(server, 'export-audit').handler({
      since: '2026-01-02T03:04:05.000Z',
      limit: 5000,
    });
    const chain = await getRegisteredMcpTool(server, 'verify-chain').handler({});

    expect(services.audit.verifyAudit).toHaveBeenCalledWith(
      { auditId: 'audit-1' },
      { ownerDid: 'did:key:human' },
    );
    expect(parseMcpToolPayload(verified)).toMatchObject({ verified: true });
    expect(services.audit.exportAudit).toHaveBeenCalledWith(
      { agentDid: undefined, since: undefined, limit: 100 },
      { ownerDid: 'did:key:human' },
    );
    expect(services.audit.exportAudit).toHaveBeenLastCalledWith(
      {
        agentDid: undefined,
        since: new Date('2026-01-02T03:04:05.000Z'),
        limit: 1000,
      },
      { ownerDid: 'did:key:human' },
    );
    expect(parseMcpToolPayload(exported)).toEqual({ records: [], count: 0 });
    expect(services.audit.verifyChain).toHaveBeenCalledWith(
      { limit: undefined },
      { ownerDid: 'did:key:human' },
    );
    expect(parseMcpToolPayload(chain)).toMatchObject({ verified: true });
  });

  it('reads mutable whoami fields and preserves identity handler dependencies', async () => {
    deps.session = { ...createMcpSession(), humanDid: 'did:key:replacement' };
    deps.trustAnchorStore = {
      list: vi.fn(() => [{ did: 'did:key:replacement', source: 'local' }]),
    } as unknown as TrustAnchorStore;
    const replacementLoggerError = vi.fn();
    deps.logger = { error: replacementLoggerError } as unknown as Logger;
    deps.bindingVcJwt = 'binding-2';
    deps.bindingExpiry = 200;
    deps.orgDomain = 'updated.example.com';

    const whoami = await getRegisteredMcpTool(server, 'whoami').handler({});
    const signed = await getRegisteredMcpTool(server, 'sign').handler({ payload: 'hello' });
    const discovered = await getRegisteredMcpTool(server, 'discover').handler({});
    const challenged = await getRegisteredMcpTool(server, 'challenge').handler({
      requestorDid: 'did:key:requestor',
      ttlSeconds: 30,
    });

    expect(parseMcpToolPayload(whoami)).toEqual({
      serverDid: 'did:key:server',
      humanDid: 'did:key:human',
      orgDomain: 'updated.example.com',
      bindingVcJwt: 'binding-2',
      bindingExpiry: 200,
      currentDidMethod: 'did:key',
    });
    expect(identity.check).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ principal: 'did:key:human', operation: 'sign' }),
    );
    expect(identity.signJwt).toHaveBeenCalledWith(
      expect.objectContaining({
        iss: 'did:key:server',
        payload: 'agents-sign-v1:hello',
      }),
    );
    expect(parseMcpToolPayload(signed)).toEqual({
      signature: 'signed-jwt',
      signerDid: 'did:key:server',
      algorithm: 'Ed25519',
    });
    expect(identity.list).toHaveBeenCalledOnce();
    expect(parseMcpToolPayload(discovered)).toEqual({
      serverDid: 'did:key:server',
      trustedAnchors: [{ did: 'did:key:trusted', source: 'local' }],
      didMethod: 'did:key',
    });
    expect(identity.check).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ principal: 'did:key:human', operation: 'challenge' }),
    );
    expect(identity.issue).toHaveBeenCalledWith({
      requestorDid: 'did:key:requestor',
      ttlSeconds: 30,
    });
    expect(parseMcpToolPayload(challenged)).toEqual(identity.challengeResult);

    identity.list.mockImplementationOnce(() => {
      throw new Error('anchor failure');
    });
    const discoveryError = await getRegisteredMcpTool(server, 'discover').handler({});
    expect(discoveryError).toMatchObject({ isError: true });
    expect(loggerError).toHaveBeenCalledWith(
      '[agents] Internal error in MCP tool handler: anchor failure',
      { handler: 'tool', error: 'anchor failure' },
    );
    expect(replacementLoggerError).not.toHaveBeenCalled();
  });

  it('keys quotas by human DID rather than the parent issuer', async () => {
    const fallbackServer = createMockMcpServer();
    registerTools(fallbackServer, {
      services,
      session,
      serverIdentity: identity.serverIdentity,
      rateLimiter: identity.rateLimiter,
      challengeStore: identity.challengeStore,
    });

    await getRegisteredMcpTool(fallbackServer, 'sign').handler({ payload: 'hello' });
    await getRegisteredMcpTool(fallbackServer, 'challenge').handler({});

    // Keying by parentIssuerDid would put every human in one organization on a shared bucket.
    expect(session.parentIssuerDid).toBe('did:key:org');
    expect(identity.check).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ principal: 'did:key:human', operation: 'sign' }),
    );
    expect(identity.check).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ principal: 'did:key:human', operation: 'challenge' }),
    );
  });

  it('spends one quota across credential issuance and delegation', async () => {
    const mintServer = createMockMcpServer();
    registerTools(mintServer, { services, session, rateLimiter: identity.rateLimiter });

    await getRegisteredMcpTool(mintServer, 'issue-credential').handler({
      agent: 'did:key:agent',
      columns: ['patients.name'],
    });
    await getRegisteredMcpTool(mintServer, 'delegate-credential').handler({
      sourceAgentDid: 'did:key:source',
      sourceCredential: 'source-jwt',
      targetAgent: 'did:key:target',
      columns: ['patients.name'],
      actions: ['read'],
      expiresIn: '1h',
    });

    expect(identity.check).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ principal: 'did:key:human', operation: 'credential-mint' }),
    );
    expect(identity.check).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ principal: 'did:key:human', operation: 'credential-mint' }),
    );
  });

  it('preserves duplicate-agent, invalid-date, audit-not-found, and safe internal errors', async () => {
    vi.mocked(services.agents.createAgent).mockRejectedValueOnce(new Error('already exists'));
    const duplicate = await getRegisteredMcpTool(server, 'create-agent').handler({
      name: 'worker',
    });
    const invalidDate = await getRegisteredMcpTool(server, 'export-audit').handler({
      since: 'not-a-date',
    });
    vi.mocked(services.audit.verifyAudit).mockResolvedValueOnce({
      error: 'NOT_FOUND',
      message: 'not found',
    });
    const notFound = await getRegisteredMcpTool(server, 'verify-audit').handler({
      auditId: 'missing',
    });

    const logger = { error: vi.fn() } as unknown as Logger;
    const errorServer = createMockMcpServer();
    const errorServices = createAgentToolServiceFakes();
    vi.mocked(errorServices.query.execute).mockRejectedValueOnce(new Error('database secret'));
    registerTools(errorServer, { services: errorServices, session, logger });
    const internal = await getRegisteredMcpTool(errorServer, 'query').handler({
      agent: 'did:key:agent',
      credential: 'jwt',
      sql: 'SELECT 1',
      table: 'patients',
    });

    expect(duplicate).toMatchObject({ isError: true });
    expect(parseMcpToolPayload(duplicate)).toEqual({
      error: 'DUPLICATE_AGENT',
      message: "Agent name 'worker' already exists",
    });
    expect(invalidDate).toMatchObject({ isError: true });
    expect(parseMcpToolPayload(invalidDate)).toEqual({
      error: 'INVALID_DATE',
      message: 'Invalid date: not-a-date',
    });
    expect(notFound).toMatchObject({ isError: true });
    expect(parseMcpToolPayload(notFound)).toEqual({ error: 'NOT_FOUND', message: 'not found' });
    expect(internal).toMatchObject({ isError: true });
    expect(parseMcpToolPayload(internal)).toEqual({
      error: 'INTERNAL_ERROR',
      message: 'An internal error occurred.',
    });
    expect(logger.error).toHaveBeenCalledWith(
      '[agents] Internal error in MCP tool handler: database secret',
      { handler: 'tool', error: 'database secret' },
    );
  });
});
