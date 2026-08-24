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

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentToolServices } from '#services/index.js';
import type { AuthenticatedSession } from '#types/auth.js';
import type { Logger } from '#observability/logger.js';
import { mcpToolInputShapes } from '#transport/index.js';
import { mapAgentScopeError } from './tool-errors.js';

interface QueryToolDependencies {
  services: Pick<AgentToolServices, 'query'>;
  session: AuthenticatedSession;
  logger?: Logger;
}

export function registerQueryTool(server: McpServer, deps: QueryToolDependencies): void {
  server.registerTool(
    'query',
    {
      description:
        'Execute a scoped SQL query with an agent-signed Verifiable Presentation. Validates the query (read-only, declared table, projection boundary), executes the original SQL, and returns decrypted rows for in-scope columns. Out-of-scope references are rejected before execution with ScopeViolationError; mutations (INSERT/UPDATE/DELETE/DDL) are rejected at parse time with QueryRejectedError.',
      inputSchema: mcpToolInputShapes.query,
    },
    async ({ agent, credential, sql, table, params }) => {
      try {
        const result = await deps.services.query.execute(
          {
            agent,
            credential,
            sql,
            table,
            params,
            requirePresentation: true,
          },
          { orgId: deps.session.parentIssuerDid },
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
