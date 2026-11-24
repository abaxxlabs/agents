import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from '#mcp/tools.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import { createAgentToolServiceFakes, createMcpSession, createMockMcpServer } from './mocks/mcp.js';

const CORE_TOOL_NAMES = [
  'query',
  'create-agent-identity',
  'issue-credential',
  'revoke-credential',
  'delegate-credential',
  'verify-audit',
  'export-audit',
  'list-agents',
  'verify-chain',
];

const IDENTITY_TOOL_NAMES = ['whoami', 'sign', 'discover', 'challenge'];

const TOOL_DESCRIPTIONS = [
  'Execute a scoped SQL query with an agent-signed Verifiable Presentation. Validates the query (read-only, declared table, projection boundary), executes the original SQL, and returns decrypted rows for in-scope columns. Out-of-scope references are rejected before execution with ScopeViolationError; mutations (INSERT/UPDATE/DELETE/DDL) are rejected at parse time with QueryRejectedError.',
  'Create a new agent identity (DID + keypair). Returns DID and public key — private key stays server-side.',
  'Issue a Verifiable Credential JWT scoping an agent to specific columns.',
  'Revoke a previously issued credential.',
  'Delegate a credential to another agent with a narrower scope. The delegated scope must be a subset of the source credential.',
  "Verify an audit record's Ed25519 signature against the agent's public key.",
  'Export filtered audit records for compliance and reporting.',
  'List registered agents and their metadata.',
  'Verify integrity within the session-visible audit window. For full root-of-chain proof, use the admin/global verify endpoint.',
  'Return the current server identity bundle: server DID, human DID, org domain, binding credential, and DID method.',
  "Sign an arbitrary payload with the server's Ed25519 key. Returns a JWT containing the domain-separated payload. Max 64KB payload.",
  'List trusted server DIDs and the current identity topology. Shows the trust boundary this server recognizes.',
  'Issue a time-bound challenge for VP (Verifiable Presentation) requests. The challenge must be included in the VP to prove freshness.',
];

function serverIdentity(): ServerIdentity {
  return {
    did: 'did:key:server',
    signer: { signJwt: vi.fn(async () => 'signed-jwt') },
    publicKey: new Uint8Array(),
    isNew: false,
  };
}

describe('MCP tool registration contract', () => {
  it('registers the exact core inventory and descriptions without identity', () => {
    const server = createMockMcpServer();

    registerTools(server, {
      services: createAgentToolServiceFakes(),
      session: createMcpSession(),
    });

    expect(server._tools.map((tool) => tool.name)).toEqual(CORE_TOOL_NAMES);
    expect(server._tools.map((tool) => tool.description)).toEqual(TOOL_DESCRIPTIONS.slice(0, 9));
  });

  it('fails before partial registration when dependencies are incomplete', () => {
    const server = createMockMcpServer();

    expect(() => registerTools(server, { session: createMcpSession() })).toThrow(
      'registerTools requires either services or scope+auditLogger dependencies.',
    );
    expect(server._tools).toEqual([]);
  });

  it('preserves the serialized schemas measured through the real MCP SDK', async () => {
    const server = new McpServer({ name: 'agents-test', version: '0.0.0' });
    registerTools(server, {
      services: createAgentToolServiceFakes(),
      session: createMcpSession(),
      serverIdentity: serverIdentity(),
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);

    try {
      const { tools } = await client.listTools();
      expect(tools.map((tool) => tool.name)).toEqual([...CORE_TOOL_NAMES, ...IDENTITY_TOOL_NAMES]);
      expect(tools.map((tool) => JSON.stringify(tool).length)).toEqual([
        957, 447, 893, 323, 1033, 336, 445, 362, 383, 287, 369, 284, 430,
      ]);
      expect(JSON.stringify({ tools }).length).toBe(6573);
      expect(createHash('sha256').update(JSON.stringify({ tools })).digest('hex')).toBe(
        'de5f8d7053b9565324096790c75c8bca505dadb543106568cfc7151204969104',
      );
    } finally {
      await client.close();
      await server.close();
    }
  });
});
