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
});
