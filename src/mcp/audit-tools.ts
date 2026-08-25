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

interface AuditToolDependencies {
  services: Pick<AgentToolServices, 'audit'>;
  session: AuthenticatedSession;
  logger?: Logger;
}

export function registerVerifyAuditTool(server: McpServer, deps: AuditToolDependencies): void {
  server.registerTool(
    'verify-audit',
    {
      description: "Verify an audit record's Ed25519 signature against the agent's public key.",
      inputSchema: {
        auditId: z.string().describe('Audit record ID'),
      },
    },
    async ({ auditId }) => {
      try {
        const result = await deps.services.audit.verifyAudit(
          { auditId },
          { ownerDid: deps.session.humanDid },
        );
        if ('error' in result) {
          return {
            content: [{ type: 'text' as const, text: JSON.stringify(result) }],
            isError: true,
          };
        }
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}

export function registerExportAuditTool(server: McpServer, deps: AuditToolDependencies): void {
  server.registerTool(
    'export-audit',
    {
      description: 'Export filtered audit records for compliance and reporting.',
      inputSchema: {
        agentDid: z.string().optional().describe('Filter by agent DID'),
        since: z.string().optional().describe('Filter since ISO date'),
        limit: z.number().optional().describe('Max records to return (default 100)'),
      },
    },
    async ({ agentDid, since, limit }) => {
      try {
        const maxRecords = Math.min(limit ?? 100, 1000);
        let sinceDate: Date | undefined;
        if (since) {
          sinceDate = new Date(since);
          if (isNaN(sinceDate.getTime())) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: JSON.stringify({
                    error: 'INVALID_DATE',
                    message: `Invalid date: ${since}`,
                  }),
                },
              ],
              isError: true,
            };
          }
        }
        const result = await deps.services.audit.exportAudit(
          {
            agentDid,
            since: sinceDate,
            limit: maxRecords,
          },
          { ownerDid: deps.session.humanDid },
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}

export function registerVerifyChainTool(server: McpServer, deps: AuditToolDependencies): void {
  server.registerTool(
    'verify-chain',
    {
      description: 'Verify the integrity of the audit hash chain. Reports any broken links.',
      inputSchema: {
        limit: z.number().optional().describe('Max records to verify (default 1000)'),
      },
    },
    async ({ limit }) => {
      try {
        const result = await deps.services.audit.verifyChain(
          { limit },
          { ownerDid: deps.session.humanDid },
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        };
      } catch (err) {
        return mapAgentScopeError(err, deps.logger);
      }
    },
  );
}
