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

/** MCP resource handlers — 4 read-only inspection resources. */

import { type McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AgentScope } from '../sql/index.js';
import type { AuditLogger } from '../audit-logger.js';
import { normalizeDomainError, toMcpErrorBody } from '../transport/index.js';
import type { Logger } from '../logger.js';
import { getLogger } from '../logger.js';

export interface ResourceDependencies {
  scope: AgentScope;
  auditLogger: AuditLogger;
  logger?: Logger;
}

export function registerResources(server: McpServer, deps: ResourceDependencies): void {
  const { scope, auditLogger, logger: injectedLogger } = deps;
  const log = getLogger(injectedLogger);

  // agent://{did} — Agent metadata (template resource)
  server.resource(
    'agent-info',
    new ResourceTemplate('agent://{did}', { list: undefined }),
    { description: 'Agent metadata by DID' },
    async (uri, variables) => {
      try {
        const did = variables.did;
        const agents = await scope.listAgents({});
        const agent = agents.find((a) => a.did === did);
        if (!agent) {
          return {
            contents: [
              {
                uri: uri.href,
                mimeType: 'application/json',
                text: JSON.stringify({ error: 'NOT_FOUND', message: `Agent ${did} not found` }),
              },
            ],
          };
        }
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify(agent),
            },
          ],
        };
      } catch (err) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: renderResourceError(err, log),
            },
          ],
        };
      }
    },
  );

  // audit://recent — Recent audit records (fixed resource)
  server.resource(
    'audit-recent',
    'audit://recent',
    { description: 'Last 50 audit records' },
    async (uri) => {
      try {
        const records = await auditLogger.export();
        const recent = records.slice(-50);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify({ records: recent, count: recent.length }),
            },
          ],
        };
      } catch (err) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: renderResourceError(err, log),
            },
          ],
        };
      }
    },
  );

  // audit://{id} — Single audit record (template resource)
  server.resource(
    'audit-record',
    new ResourceTemplate('audit://{id}', { list: undefined }),
    { description: 'Single audit record by ID' },
    async (uri, variables) => {
      try {
        const id = variables.id;
        const records = await auditLogger.export();
        const record = records.find((r) => r.id === id);
        if (!record) {
          return {
            contents: [
              {
                uri: uri.href,
                mimeType: 'application/json',
                text: JSON.stringify({
                  error: 'NOT_FOUND',
                  message: `Audit record ${id} not found`,
                }),
              },
            ],
          };
        }
        const verifyResult = await scope.verify(record);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify({ record, verified: verifyResult.valid }),
            },
          ],
        };
      } catch (err) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: renderResourceError(err, log),
            },
          ],
        };
      }
    },
  );

  // config://status — Server status (fixed resource)
  server.resource(
    'config-status',
    'config://status',
    { description: 'Server status: agents, audit records, encrypted columns' },
    async (uri) => {
      try {
        const status = await scope.getServerStatus();
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify(status),
            },
          ],
        };
      } catch (err) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: renderResourceError(err, log),
            },
          ],
        };
      }
    },
  );
}

function renderResourceError(err: unknown, injectedLogger?: Logger): string {
  const logger = getLogger(injectedLogger);
  const normalized = normalizeDomainError(err);
  if (normalized.code === 'INTERNAL_ERROR' && err instanceof Error) {
    logger.error('[agents] Internal error in MCP resource handler: ' + err.message, {
      handler: 'resource', error: err.message,
    });
  }
  return JSON.stringify(toMcpErrorBody(normalized));
}
