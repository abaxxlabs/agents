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

export interface McpHttpBearerAuthInput {
  allowNoAuth?: boolean;
  bearerAuth?: { getValidTokens: () => string[] };
}

export type McpHttpBearerResolution =
  | { ok: true; count: number }
  | { ok: false; reason: string };

export function resolveMcpHttpBearerTokenCount(
  options: Pick<McpHttpBearerAuthInput, 'bearerAuth'>,
): McpHttpBearerResolution {
  if (!options.bearerAuth) {
    return { ok: false, reason: 'bearerAuth is not configured' };
  }
  let tokens: string[];
  try {
    tokens = options.bearerAuth.getValidTokens();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, reason: `getValidTokens() threw: ${msg}` };
  }
  if (!Array.isArray(tokens)) {
    return { ok: false, reason: 'getValidTokens() did not return an array' };
  }
  const nonEmpty = tokens.map((t) => (typeof t === 'string' ? t.trim() : '')).filter(Boolean);
  if (nonEmpty.length === 0) {
    return { ok: false, reason: 'getValidTokens() returned no non-empty tokens' };
  }
  return { ok: true, count: nonEmpty.length };
}

export type McpHttpBearerBootResult =
  | { action: 'ok' }
  | { action: 'exit'; code: number; stderrLines: string[] }
  | { action: 'warn_no_auth'; stderrLines: string[] };

export function evaluateMcpHttpBearerBoot(
  options: McpHttpBearerAuthInput,
  nodeEnv: string | undefined,
  precomputedResolution?: McpHttpBearerResolution,
): McpHttpBearerBootResult {
  const envLower = (nodeEnv ?? '').toLowerCase();
  const isDevOrTest = envLower === 'development' || envLower === 'test';
  const isProduction = envLower === 'production';

  const resolved = precomputedResolution ?? resolveMcpHttpBearerTokenCount(options);
  if (resolved.ok) {
    return { action: 'ok' };
  }

  if (options.allowNoAuth && !isDevOrTest) {
    return {
      action: 'exit',
      code: 1,
      stderrLines: ['[agents] --allow-no-auth requires NODE_ENV=development or NODE_ENV=test'],
    };
  }

  if (isProduction) {
    return {
      action: 'exit',
      code: 1,
      stderrLines: [
        '[agents] HTTP transport in NODE_ENV=production requires bearerAuth with at least one non-empty token from getValidTokens(). Misconfiguration: ' +
          resolved.reason +
          '.',
      ],
    };
  }

  if (isDevOrTest && options.allowNoAuth) {
    return {
      action: 'warn_no_auth',
      stderrLines: [
        '[agents] WARNING: HTTP MCP is serving without bearer auth (--allow-no-auth). All MCP endpoints except /health are anonymously callable; wire bearerAuth in production.',
      ],
    };
  }

  return {
    action: 'exit',
    code: 1,
    stderrLines: [
      '[agents] HTTP transport requires bearerAuth with at least one non-empty token from getValidTokens(), or pass --allow-no-auth with NODE_ENV=development|test. ' +
        resolved.reason +
        '.',
    ],
  };
}
