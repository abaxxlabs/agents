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

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentToolServices } from '#services/index.js';
import type { AuthenticatedSession } from '#types/auth.js';
import type { Logger } from '#observability/logger.js';
import { mapAgentScopeError } from './tool-errors.js';

interface AgentToolDependencies {
  services: Pick<AgentToolServices, 'agents'>;
  session: AuthenticatedSession;
  logger?: Logger;
}

export function registerCreateAgentTool(server: McpServer, deps: AgentToolDependencies): void {
  server.registerTool(
    'create-agent',
    {
      description:
        'Create a new agent identity (DID + keypair). Returns DID and public key — private key stays server-side.',
      inputSchema: {
        name: z.string().describe('Agent name'),
        ownerDid: z.string().optional().describe('Owner DID (defaults to session human)'),
      },
    },
    async ({ name, ownerDid }) => {
      try {
        const createdAgent = await deps.services.agents.createAgent({
          name,
          ownerDid: ownerDid ?? deps.session.humanDid,
        });
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                did: createdAgent.did,
                name: createdAgent.name,
                ownerDid: createdAgent.ownerDid,
                publicKey: Buffer.from(createdAgent.publicKey).toString('base64'),
              }),
            },
          ],
        };
      } catch (err) {
        if (
          (err instanceof Error && err.message.includes('duplicate key')) ||
          (err instanceof Error && err.message.includes('already exists'))
        ) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({
                  error: 'DUPLICATE_AGENT',
                  message: `Agent name '${name}' already exists`,
                }),
              },
            ],
            isError: true,
          };
        }
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}

export function registerListAgentsTool(server: McpServer, deps: AgentToolDependencies): void {
  server.registerTool(
    'list-agents',
    {
      description: 'List registered agents and their metadata.',
      inputSchema: {
        ownerDid: z.string().optional().describe('Filter by owner DID'),
        limit: z.number().optional().describe('Max agents to return (default 100)'),
      },
    },
    async ({ ownerDid, limit }) => {
      try {
        const agents = await deps.services.agents.listAgents({
          ownerDid,
          limit: Math.min(limit ?? 100, 100),
        });
        return {
          content: [
            { type: 'text' as const, text: JSON.stringify({ agents, count: agents.length }) },
          ],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}
