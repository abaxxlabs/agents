import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from '#mcp/tools.js';
import { registerResources, type ResourceServices } from '#mcp/resources.js';
import type { AgentScope } from '#sql/index.js';
import type { AuditLogger } from '#audit/index.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import {
  createAgentToolServiceFakes,
  createMcpSession,
  createMockMcpServer,
  getRegisteredMcpTool,
} from './mocks/mcp.js';

const CORE_TOOL_NAMES = [
  'query',
  'create-agent',
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
  'Verify the integrity of the audit hash chain. Reports any broken links.',
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

  it('appends identity tools in order even without a trust anchor store', () => {
    const server = createMockMcpServer();

    registerTools(server, {
      services: createAgentToolServiceFakes(),
      session: createMcpSession(),
      serverIdentity: serverIdentity(),
    });

    expect(server._tools.map((tool) => tool.name)).toEqual([
      ...CORE_TOOL_NAMES,
      ...IDENTITY_TOOL_NAMES,
    ]);
    expect(server._tools.map((tool) => tool.description)).toEqual(TOOL_DESCRIPTIONS);
  });

  it('fails before partial registration when dependencies are incomplete', () => {
    const server = createMockMcpServer();

    expect(() => registerTools(server, { session: createMcpSession() })).toThrow(
      'registerTools requires either services or scope+auditLogger dependencies.',
    );
    expect(server._tools).toEqual([]);
  });

  it('keeps the scope and audit logger fallback path functional', async () => {
    const server = createMockMcpServer();
    const scope = {
      query: vi.fn(async () => ({ rows: [], metadata: { rowCount: 0 } })),
      createAgent: vi.fn(),
      listAgents: vi.fn(),
      delegateCredential: vi.fn(),
      verify: vi.fn(),
    } as unknown as AgentScope;
    const auditLogger = { export: vi.fn() } as unknown as AuditLogger;

    registerTools(server, { scope, auditLogger, session: createMcpSession() });

    expect(server._tools.map((tool) => tool.name)).toEqual(CORE_TOOL_NAMES);
    await getRegisteredMcpTool(server, 'query').handler({
      agent: 'did:key:agent',
      credential: 'jwt',
      sql: 'SELECT id FROM patients',
      table: 'patients',
    });
    expect(scope.query).toHaveBeenCalledWith(
      expect.objectContaining({
        agent: 'did:key:agent',
        credential: 'jwt',
        requirePresentation: true,
        orgId: 'did:key:org',
      }),
    );
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
        957, 438, 912, 323, 1052, 336, 445, 362, 329, 287, 369, 284, 430,
      ]);
      expect(JSON.stringify({ tools }).length).toBe(6548);
      expect(createHash('sha256').update(JSON.stringify({ tools })).digest('hex')).toBe(
        'd56822258633b9e34d6622447453c3444703b8c5b5ad63b1fb1978d7c830d6a2',
      );
    } finally {
      await client.close();
      await server.close();
    }
  });
});

const ROOT = resolve(import.meta.dirname, '..');

const REGISTRATION_SOURCES = [
  'src/mcp/query-tools.ts',
  'src/mcp/agent-tools.ts',
  'src/mcp/credential-tools.ts',
  'src/mcp/audit-tools.ts',
  'src/mcp/identity-tools.ts',
  'src/mcp/resources.ts',
  'src/mcp/rest-bridge.ts',
];

function createResourceServiceFakes(): ResourceServices {
  return {
    agents: {
      getAgent: vi.fn(async ({ did }: { did: string }) => ({ did, name: 'Agent' })),
    },
    audit: {
      getRecentAudit: vi.fn(async () => ({ records: [], count: 0 })),
      verifyAudit: vi.fn(async () => ({ verified: true, record: { id: 'audit-1' } })),
    },
    status: {
      getStatus: vi.fn(async () => ({
        agentCount: 0,
        auditRecordCount: 0,
        encryptedColumns: [],
      })),
    },
  } as unknown as ResourceServices;
}

describe('MCP resource registration contract', () => {
  it('lists the two fixed resources and two templates unchanged', async () => {
    const server = new McpServer({ name: 'agents-test', version: '0.0.0' });
    registerResources(server, { services: createResourceServiceFakes() });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);

    try {
      const { resources } = await client.listResources();
      expect(resources).toEqual([
        {
          uri: 'audit://recent',
          name: 'audit-recent',
          description: 'Last 50 audit records',
        },
        {
          uri: 'config://status',
          name: 'config-status',
          description: 'Server status: agents, audit records, encrypted columns',
        },
      ]);

      const { resourceTemplates } = await client.listResourceTemplates();
      expect(resourceTemplates).toEqual([
        {
          name: 'agent-info',
          uriTemplate: 'agent://{did}',
          description: 'Agent metadata by DID',
        },
        {
          name: 'audit-record',
          uriTemplate: 'audit://{id}',
          description: 'Single audit record by ID',
        },
      ]);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('routes reads to fixed resources and template handlers with variables unchanged', async () => {
    const services = createResourceServiceFakes();
    const server = new McpServer({ name: 'agents-test', version: '0.0.0' });
    registerResources(server, { services });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await client.connect(clientTransport);

    try {
      const recent = await client.readResource({ uri: 'audit://recent' });
      expect(recent.contents).toHaveLength(1);
      expect(recent.contents[0].uri).toBe('audit://recent');
      expect(recent.contents[0].mimeType).toBe('application/json');
      expect(JSON.parse(recent.contents[0].text as string)).toEqual({ records: [], count: 0 });
      expect(services.audit.getRecentAudit).toHaveBeenCalledWith({ limit: 50 });

      const status = await client.readResource({ uri: 'config://status' });
      expect(JSON.parse(status.contents[0].text as string)).toEqual({
        agentCount: 0,
        auditRecordCount: 0,
        encryptedColumns: [],
      });
      expect(services.status.getStatus).toHaveBeenCalledOnce();

      const agent = await client.readResource({ uri: 'agent://agent-1' });
      expect(JSON.parse(agent.contents[0].text as string)).toEqual({
        did: 'agent-1',
        name: 'Agent',
      });
      expect(services.agents.getAgent).toHaveBeenCalledWith({ did: 'agent-1' });

      const record = await client.readResource({ uri: 'audit://audit-1' });
      expect(JSON.parse(record.contents[0].text as string)).toEqual({
        record: { id: 'audit-1' },
        verified: true,
      });
      expect(services.audit.verifyAudit).toHaveBeenCalledWith({ auditId: 'audit-1' });
    } finally {
      await client.close();
      await server.close();
    }
  });
});

describe('deprecated registration API regression', () => {
  it('contains no executable deprecated tool or resource registrations in MCP sources', () => {
    let toolRegistrations = 0;
    let resourceRegistrations = 0;
    for (const sourcePath of REGISTRATION_SOURCES) {
      const source = readFileSync(resolve(ROOT, sourcePath), 'utf8');
      expect(source, sourcePath).not.toMatch(/\.tool\(/);
      expect(source, sourcePath).not.toMatch(/\.resource\(/);
      toolRegistrations += source.match(/server\.registerTool\(/g)?.length ?? 0;
      resourceRegistrations += source.match(/server\.registerResource\(/g)?.length ?? 0;
    }
    expect(toolRegistrations).toBe(26);
    expect(resourceRegistrations).toBe(4);
  });
});
