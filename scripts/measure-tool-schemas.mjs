#!/usr/bin/env node

/**
 * Measure the token cost of eager MCP ListTools schema loading.
 *
 * Uses the real MCP SDK (McpServer + Client + InMemoryTransport) and the
 * compiled MCP tool registration implementation from src/mcp/tools.ts.
 *
 * Run: node scripts/measure-tool-schemas.mjs
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from '../dist/mcp/tools.js';

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

function createStubServices() {
  return {
    query: {
      execute: async () => ({
        rows: [],
        metadata: {
          agent: '',
          owner: '',
          columnsDecrypted: [],
          columnsEncrypted: [],
          rowCount: 0,
          queryDurationMs: 0,
          auditId: '',
        },
      }),
    },
    agents: {
      createAgent: async () => ({
        did: '',
        name: '',
        ownerDid: '',
        publicKey: new Uint8Array(),
        createdAt: '',
      }),
      listAgents: async () => [],
    },
    credentials: {
      issueCredential: async () => ({ credential: 'stub' }),
      delegateCredential: async () => ({ credential: 'stub' }),
      listCredentials: async () => ({ credentials: [], count: 0 }),
      revokeCredential: async ({ credentialId }) => ({ revoked: true, credentialId }),
    },
    audit: {
      exportAudit: async () => ({ records: [], count: 0 }),
      verifyAudit: async () => ({ error: 'NOT_FOUND', message: 'stub' }),
      verifyChain: async () => ({ verified: true, recordsChecked: 0, brokenLinks: [] }),
    },
  };
}

function projectChars(toolCount, avgToolChars, payloadOverheadChars) {
  return payloadOverheadChars + avgToolChars * toolCount;
}

async function main() {
  const server = new McpServer({ name: 'agents', version: '0.0.0' });
  registerTools(server, {
    session: {
      humanDid: 'did:key:human',
      parentIssuerDid: 'did:key:issuer',
      scopeCeiling: undefined,
    },
    services: createStubServices(),
    serverIdentity: {
      did: 'did:key:server',
      signer: { signJwt: async () => 'stub-jwt' },
    },
    trustAnchorStore: { list: () => [] },
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const client = new Client({ name: 'test-client', version: '1.0' });
  await client.connect(clientTransport);

  const result = await client.listTools();
  const payload = { tools: result.tools };
  const prettyJson = JSON.stringify(payload, null, 2);
  const compactJson = JSON.stringify(payload);
  const compactToolChars = result.tools.map(tool => JSON.stringify(tool).length);
  const totalCompactToolChars = compactToolChars.reduce((sum, chars) => sum + chars, 0);
  const payloadOverheadChars = compactJson.length - totalCompactToolChars;
  const avgCompactToolChars = totalCompactToolChars / result.tools.length;

  const breakdown = result.tools.map(tool => {
    const chars = JSON.stringify(tool).length;
    return { name: tool.name, chars, estTokens: Math.round(chars / 4) };
  });

  const coreTools = result.tools.filter(tool => CORE_TOOL_NAMES.includes(tool.name));
  const identityTools = result.tools.filter(tool => !CORE_TOOL_NAMES.includes(tool.name));
  const coreCompactJson = JSON.stringify({ tools: coreTools });
  const identityCompactJson = JSON.stringify({ tools: identityTools });

  const currentCompactChars = projectChars(result.tools.length, avgCompactToolChars, payloadOverheadChars);
  const x2CompactChars = projectChars(result.tools.length * 2, avgCompactToolChars, payloadOverheadChars);
  const x5CompactChars = projectChars(result.tools.length * 5, avgCompactToolChars, payloadOverheadChars);
  const x100CompactChars = projectChars(100, avgCompactToolChars, payloadOverheadChars);
  const opendevThresholdTools = Math.round((80_000 * 4 - payloadOverheadChars) / avgCompactToolChars);

  console.log('═══════════════════════════════════════════════════════');
  console.log('  MCP ListTools Schema Payload — Measured via Real SDK');
  console.log('═══════════════════════════════════════════════════════\n');

  console.log('Tool registration source: dist/mcp/tools.js (built from src/mcp/tools.ts)');
  console.log(`Tool count: ${result.tools.length} (${coreTools.length} core + ${identityTools.length} identity)`);
  console.log(`\nCore tools (${coreTools.length}):     ${(coreCompactJson.length / 1024).toFixed(1)} KB  ~${Math.round(coreCompactJson.length / 4).toLocaleString()} tokens`);
  console.log(`Identity tools (${identityTools.length}): ${(identityCompactJson.length / 1024).toFixed(1)} KB  ~${Math.round(identityCompactJson.length / 4).toLocaleString()} tokens`);
  console.log(`Compact payload: ${(currentCompactChars / 1024).toFixed(1)} KB  ~${Math.round(currentCompactChars / 4).toLocaleString()} tokens (4:1)`);
  console.log(`Pretty payload:  ${(prettyJson.length / 1024).toFixed(1)} KB  ~${Math.round(prettyJson.length / 4).toLocaleString()} tokens (4:1)`);
  console.log(`Compact chars:   ${compactJson.length.toLocaleString()}`);
  console.log(`Pretty chars:    ${prettyJson.length.toLocaleString()}`);
  console.log(`Payload overhead: ${payloadOverheadChars} chars`);
  console.log(`Avg tool body:   ${avgCompactToolChars.toFixed(1)} chars  ~${Math.round(avgCompactToolChars / 4)} tok`);

  console.log('\n───────────────── Per-Tool ──────────────────────────');
  breakdown.forEach(tool => {
    const pct = (tool.chars / compactJson.length * 100).toFixed(1);
    console.log(`  ${tool.name.padEnd(20)} ${tool.chars.toString().padStart(5)} chars  ~${tool.estTokens.toString().padStart(4)} tok  ${pct}%`);
  });

  console.log('\n─────────────── Projections (compact basis) ─────────');
  console.log(`Current (${result.tools.length} tools): ${(currentCompactChars / 1024).toFixed(1)} KB  ~${Math.round(currentCompactChars / 4).toLocaleString()} tok`);
  console.log(`2x (~${result.tools.length * 2} tools):    ${(x2CompactChars / 1024).toFixed(1)} KB  ~${Math.round(x2CompactChars / 4).toLocaleString()} tok`);
  console.log(`5x (~${result.tools.length * 5} tools):    ${(x5CompactChars / 1024).toFixed(1)} KB  ~${Math.round(x5CompactChars / 4).toLocaleString()} tok`);
  console.log(`100 tools:          ${(x100CompactChars / 1024).toFixed(1)} KB  ~${Math.round(x100CompactChars / 4).toLocaleString()} tok`);

  console.log('\n─────────────── Context Budget Impact ───────────────');
  const budgets = [
    { name: 'Claude Opus', tokens: 100_000 },
    { name: 'Claude Sonnet', tokens: 200_000 },
    { name: 'GPT-4o', tokens: 128_000 },
    { name: 'Gemini 1.5 Pro', tokens: 1_000_000 },
  ];
  budgets.forEach(budget => {
    const currentPct = (Math.round(currentCompactChars / 4) / budget.tokens * 100).toFixed(1);
    const x2Pct = (Math.round(x2CompactChars / 4) / budget.tokens * 100).toFixed(1);
    const x5Pct = (Math.round(x5CompactChars / 4) / budget.tokens * 100).toFixed(1);
    const x100Pct = (Math.round(x100CompactChars / 4) / budget.tokens * 100).toFixed(1);
    console.log(`  ${budget.name.padEnd(18)} (${(budget.tokens / 1000).toFixed(0)}K):  cur=${currentPct}%  2x=${x2Pct}%  5x=${x5Pct}%  100=${x100Pct}%`);
  });

  console.log('\n  OPENDEV paper threshold (40% of Sonnet 200K = 80K tok):');
  console.log(`  Would hit 40% at ~${opendevThresholdTools.toLocaleString()} tools`);

  console.log('\n═══════════════════════════════════════════════════════\n');

  await client.close();
  server.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
