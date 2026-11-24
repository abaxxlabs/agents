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

/**
 * Environment bridge for the MCP host. The library never reads identity or trust settings from
 * the environment; the `agents mcp` command does it here, at its boundary.
 */

import type { McpCliOptions } from './index.js';

export type McpHostOptions = Pick<McpCliOptions, 'keystorePath' | 'trustedServers'>;

/** `agents mcp` flags that take precedence over the environment. */
export interface McpHostFlags {
  keystore?: string;
}

/**
 * Host options from `env`. Lists are comma-separated, trimmed and de-duplicated, and empty
 * values count as unset.
 */
export function resolveMcpHostOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): McpHostOptions {
  const keystorePath = envValue(env.AGENTS_KEYSTORE_PATH);
  const trustedServers = envList(env.AGENTS_TRUSTED_SERVERS);
  return {
    ...(keystorePath !== undefined && { keystorePath }),
    ...(trustedServers.length > 0 && { trustedServers }),
  };
}

/** Overlays `agents mcp` flags on options resolved from the environment. */
export function withMcpHostFlags(options: McpHostOptions, flags: McpHostFlags): McpHostOptions {
  const keystorePath = envValue(flags.keystore);
  return {
    ...options,
    ...(keystorePath !== undefined && { keystorePath }),
  };
}

/** A trimmed environment value, or undefined when it is empty or unset. */
export function envValue(raw: string | undefined): string | undefined {
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

/** A comma-separated environment value as a trimmed, de-duplicated list. */
export function envList(raw: string | undefined): string[] {
  const items = new Set<string>();
  for (const part of (raw ?? '').split(',')) {
    const item = part.trim();
    if (item) items.add(item);
  }
  return [...items];
}
