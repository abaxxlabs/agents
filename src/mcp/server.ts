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

/** MCP Server factory — creates and configures McpServer with tools and resources. */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { AgentToolServices } from '#services/index.js';
import {
  registerTools,
  resolveServices,
  type ToolDependencies,
  type ToolServiceFallbackDependencies,
} from './tools.js';
import { registerResources, type ResourceServices } from './resources.js';
import type { McpBearerAuthOptions } from './auth.js';

/** @internal Exported for testing only. Skips package.json stubs without a version field. */
export function getVersion(candidates?: string[]): string {
  try {
    const paths = candidates ?? defaultVersionCandidates();
    for (const p of paths) {
      try {
        const v = JSON.parse(readFileSync(p, 'utf-8')).version;
        if (typeof v === 'string' && v.length > 0) return v;
      } catch {
        /* try next */
      }
    }
  } catch {
    /* fall through */
  }
  return '0.0.0';
}

function defaultVersionCandidates(): string[] {
  const base = typeof __dirname !== 'undefined' ? __dirname : process.cwd();
  return [
    resolve(base, '../../package.json'),
    resolve(base, '../../../package.json'),
    resolve(base, '../package.json'),
    resolve(process.cwd(), 'package.json'),
  ];
}

const version = getVersion();

export interface McpServerOptions
  extends ToolDependencies, Required<ToolServiceFallbackDependencies> {
  /**
   * Bearer auth config for HTTP transport.
   *
   * When provided, the HTTP handler in index.ts creates a McpBearerAuth guard
   * and validates every /sse and /messages request. Stdio transport ignores this.
   *
   * getValidTokens returns the current set of valid bearer tokens. Typically
   * [currentToken] in steady state, [newToken, oldToken] during rotation.
   * See OVERLAP_WINDOW_SECONDS in auth.ts for rotation semantics.
   */
  bearerAuth?: McpBearerAuthOptions;
}

export function createMcpServer(options: McpServerOptions): McpServer {
  const server = new McpServer({
    name: 'agents',
    version,
  });

  const services = resolveServices(options);
  registerTools(server, { ...options, services });
  let resourceServices: ResourceServices;
  if (supportsResources(services)) {
    resourceServices = services;
  } else {
    const fallback = resolveServices({ ...options, services: undefined });
    if (!supportsResources(fallback)) {
      throw new Error('MCP resource services are unavailable.');
    }
    resourceServices = fallback;
  }
  registerResources(server, { services: resourceServices, logger: options.logger });

  return server;
}

function supportsResources(services: AgentToolServices): services is ResourceServices {
  return Boolean(services.agents.getAgent && services.audit.getRecentAudit && services.status);
}

export async function connectStdio(server: McpServer): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

export { McpServer, StdioServerTransport };
