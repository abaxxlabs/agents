import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ChallengeStore } from '#mcp/challenge-store.js';
import type { McpServerOptions } from '#mcp/server.js';
import type { AgentScope } from '#sql/index.js';
import type { AuthenticatedSession } from '#types/index.js';
import type { AuditLogger } from '#audit/index.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';
import { generateDidKey, createSigner } from '#auth/index.js';

function createPhase2Fixtures() {
  const server = generateDidKey();
  const human = generateDidKey();

  const serverIdentity: ServerIdentity = {
    did: server.did,
    signer: createSigner(server.privateKey),
    publicKey: server.publicKey,
    isNew: false,
  };

  const trustAnchorStore = new LocalTrustAnchorStore({
    ownServerDid: server.did,
  });

  const challengeStore = new ChallengeStore();

  const scope = {
    query: vi.fn(),
    createAgentIdentity: vi.fn(),
    verify: vi.fn(),
    getAgent: vi.fn(),
    listAgents: vi.fn(),
    getServerStatus: vi.fn(),
    close: vi.fn(),
    auditLoggerInstance: { export: vi.fn().mockResolvedValue([]) },
  } as unknown as AgentScope;

  const session = {
    humanDid: human.did,
    issueCredential: vi.fn(),
    revokeCredential: vi.fn(),
  } as unknown as AuthenticatedSession;

  const auditLogger = { export: vi.fn().mockResolvedValue([]) } as unknown as AuditLogger;

  const deps: McpServerOptions = {
    scope,
    session,
    auditLogger,
    serverIdentity,
    trustAnchorStore,
    challengeStore,
    bindingVcJwt: 'eyJ.mock.binding',
    bindingExpiry: Math.floor(Date.now() / 1000) + 3600,
    orgDomain: 'abaxx.tech',
  };

  return {
    server,
    human,
    serverIdentity,
    trustAnchorStore,
    challengeStore,
    deps,
    scope,
    session,
    auditLogger,
  };
}

describe('ChallengeStore', () => {
  let store: ChallengeStore;

  beforeEach(() => {
    store = new ChallengeStore();
  });

  describe('consume', () => {
    it('rejects replay — same challenge consumed twice', () => {
      const { challenge } = store.issue();
      const first = store.consume(challenge);
      expect(first.valid).toBe(true);

      const replay = store.consume(challenge);
      expect(replay.valid).toBe(false);
      expect(replay.reason).toContain('replay');
    });

    it('rejects challenge with forged HMAC', () => {
      const { challenge } = store.issue();
      const payload = JSON.parse(Buffer.from(challenge, 'base64url').toString('utf-8'));
      payload.h = 'deadbeef'.repeat(8);
      const forged = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');

      const result = store.consume(forged);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('HMAC');
    });
  });
});

describe('MCP Identity Tools', () => {
  describe('sign tool contract', () => {
    it('server signer produces valid JWTs', async () => {
      const { serverIdentity } = createPhase2Fixtures();
      const jwt = await serverIdentity.signer.signJwt({
        iss: serverIdentity.did,
        iat: Math.floor(Date.now() / 1000),
        payload: 'agents-sign-v1:test-payload',
      });
      expect(jwt).toMatch(/^eyJ/); // JWT header starts with base64url-encoded '{"'
      expect(jwt.split('.')).toHaveLength(3);
    });
  });
});
