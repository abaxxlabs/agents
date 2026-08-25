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
import type {
  AgentDirectoryService,
  AgentToolServices,
  AuditService,
  StatusService,
} from '#services/index.js';
import { normalizeDomainError, toMcpErrorBody } from '#transport/index.js';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

export interface ResourceServices extends AgentToolServices {
  agents: AgentDirectoryService & Required<Pick<AgentDirectoryService, 'getAgent'>>;
  audit: AuditService & Required<Pick<AuditService, 'getRecentAudit'>>;
  status: StatusService;
}

export interface ResourceDependencies {
  services: ResourceServices;
  logger?: Logger;
}

export function registerResources(server: McpServer, deps: ResourceDependencies): void {
  const { services, logger: injectedLogger } = deps;
  const log = getLogger(injectedLogger);

  // agent://{did} — Agent metadata (template resource)
  server.registerResource(
    'agent-info',
    new ResourceTemplate('agent://{did}', { list: undefined }),
    { description: 'Agent metadata by DID' },
    async (uri, variables) => {
      try {
        const did = variables.did as string;
        const agent = await services.agents.getAgent({ did });
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
  server.registerResource(
    'audit-recent',
    'audit://recent',
    { description: 'Last 50 audit records' },
    async (uri) => {
      try {
        const recent = await services.audit.getRecentAudit({ limit: 50 });
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify(recent),
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
  server.registerResource(
    'audit-record',
    new ResourceTemplate('audit://{id}', { list: undefined }),
    { description: 'Single audit record by ID' },
    async (uri, variables) => {
      try {
        const id = variables.id as string;
        const result = await services.audit.verifyAudit({ auditId: id });
        if ('error' in result) {
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
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: 'application/json',
              text: JSON.stringify({ record: result.record, verified: result.verified }),
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
  server.registerResource(
    'config-status',
    'config://status',
    { description: 'Server status: agents, audit records, encrypted columns' },
    async (uri) => {
      try {
        const status = await services.status.getStatus();
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
      handler: 'resource',
      error: err.message,
    });
  }
  return JSON.stringify(toMcpErrorBody(normalized));
}
