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
 * id-sdk MCP adapter — translates the structural IdSdkInstance shape into MCP tool calls.
 *
 * Private key material stays inside the MCP server process. Function-valued signers
 * cannot cross JSON-RPC, so the adapter strips them and lets the server obtain signer
 * options from its connected session.
 *
 * Exported only from `@abaxxlabs/agents/id-sdk-mcp` — not in the main entry point,
 * so consumers who never use the MCP bridge pay no startup or lifecycle cost.
 */

import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { IdSdkInstance } from './types.js';

export interface IdSdkMcpConnectOptions {
  connectedDid?: string;
  didMethod?: 'ion' | 'dht' | 'key';
  sync?: string;
  queueWhenOffline?: boolean;
  flushWhenOnline?: boolean;
  passphrase?: string;
  dwnEndpoints?: string[];
  dhtRelayUrl?: string;
}

export interface IdSdkMcpClientOptions {
  /**
   * Executable used to start the MCP server. Defaults to `node`.
   *
   * Consumers can point this at a supervised wrapper if the platform wants
   * custom env isolation, tracing, or secret injection around the server.
   */
  command?: string;
  /**
   * Arguments for `command`. Defaults to the vendored server path.
   *
   * Override this when running a separately installed id-sdk-mcp server build.
   */
  args?: string[];
  /** Working directory for the MCP server process. */
  cwd?: string;
  /** Environment passed to the MCP server process. */
  env?: Record<string, string>;
  /** Whether stderr should be inherited or piped by the MCP transport. */
  stderr?: 'pipe' | 'inherit' | 'ignore';
  /** Optional `connect` tool call performed before returning the adapter. */
  connect?: IdSdkMcpConnectOptions;
}

export type IdSdkMcpToolCaller = (name: string, args: Record<string, unknown>) => Promise<unknown>;

export interface McpBackedIdSdkInstance extends IdSdkInstance {
  /** Low-level escape hatch for tools not yet surfaced by the structural SDK API. */
  callTool: IdSdkMcpToolCaller;
  /** Close the MCP client and the stdio child process it owns. */
  close(): Promise<void>;
}

function findUp(startDir: string, relativePath: string): string | undefined {
  let current = path.resolve(startDir);

  while (true) {
    const candidate = path.join(current, relativePath);
    if (existsSync(candidate)) {
      return candidate;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

/**
 * Resolve the vendored server path without `import.meta.url`.
 * CJS output cannot use import.meta — resolution is CWD-based with a package-install fallback.
 */
export function resolveVendoredIdSdkMcpServerPath(cwd = process.cwd()): string {
  const explicit = process.env.AGENTS_ID_SDK_MCP_SERVER;
  if (explicit) {
    return explicit;
  }

  const fromCwd = findUp(cwd, path.join('vendor', 'id-sdk-mcp', 'server.mjs'));
  if (fromCwd) {
    return fromCwd;
  }

  try {
    const requireFromCwd = createRequire(path.join(cwd, 'agents-id-sdk-mcp-resolver.cjs'));
    const subpath = requireFromCwd.resolve('@abaxxlabs/agents/id-sdk-mcp');
    const candidates = [
      path.resolve(path.dirname(subpath), '..', 'vendor', 'id-sdk-mcp', 'server.mjs'),
      path.resolve(path.dirname(subpath), '..', '..', 'vendor', 'id-sdk-mcp', 'server.mjs'),
    ];
    const found = candidates.find((candidate) => existsSync(candidate));
    if (found) {
      return found;
    }
  } catch {
    // Fall through to the relative path so callers get a useful spawn error.
  }

  return path.join(cwd, 'vendor', 'id-sdk-mcp', 'server.mjs');
}

function withoutFunctionValues(value: unknown): unknown {
  if (typeof value === 'function') {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map(withoutFunctionValues);
  }

  if (value && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (typeof child !== 'function') {
        result[key] = withoutFunctionValues(child);
      }
    }
    return result;
  }

  return value;
}

function parseMcpToolResult(result: unknown): unknown {
  if (
    result &&
    typeof result === 'object' &&
    'isError' in result &&
    (result as { isError?: boolean }).isError
  ) {
    throw new Error(`[agents] id-sdk-mcp tool returned an error: ${JSON.stringify(result)}`);
  }

  if (result && typeof result === 'object' && 'structuredContent' in result) {
    const structured = (result as { structuredContent?: unknown }).structuredContent;
    if (structured !== undefined) {
      return structured;
    }
  }

  const content =
    result && typeof result === 'object'
      ? (result as { content?: Array<{ type: string; text?: string }> }).content
      : undefined;
  const textItem = content?.find((item) => item.type === 'text' && typeof item.text === 'string');
  if (!textItem?.text) {
    return result;
  }

  try {
    return JSON.parse(textItem.text);
  } catch {
    return textItem.text;
  }
}

/**
 * Build an id-sdk-shaped object from a generic MCP tool caller.
 *
 * Tests use this to verify method-to-tool mapping without launching the real
 * server. Production callers normally use `connectIdSdkMcp()` below.
 */
export function createIdSdkMcpAdapter(
  callTool: IdSdkMcpToolCaller,
  options: {
    connectedDid?: string;
    close?: () => Promise<void>;
  } = {},
): McpBackedIdSdkInstance {
  const close = options.close ?? (async () => {});

  const vc = {
    createCredential(
      issuer: string,
      subject: string,
      data: unknown,
      type?: string,
    ): Promise<unknown> {
      return callTool('vc_create_credential', { issuer, subject, data, type });
    },

    signCredential(vcPayload: unknown, signOptions: Record<string, unknown> = {}): Promise<string> {
      return callTool('vc_sign_credential', {
        vc: vcPayload,
        signOptions: withoutFunctionValues(signOptions),
      }) as Promise<string>;
    },

    getSignerOptions(issuerDid: string, subjectDid: string) {
      return callTool('vc_get_signer_options', {
        issuerDid,
        subjectDid,
      }) as Promise<{ kid: string; issuerDid: string; subjectDid: string; signer: (data: Uint8Array) => Promise<Uint8Array> }>;
    },

    verifyJWT(jwt: string): Promise<boolean> {
      return callTool('vc_verify_jwt', { jwt }) as Promise<boolean>;
    },

    decodeJWT(jwt: string) {
      return callTool('vc_decode_jwt', { jwt }) as Promise<{ header: Record<string, unknown>; payload: Record<string, unknown>; signature: string }>;
    },

    parseJWT(jwt: string): Promise<unknown> {
      return callTool('vc_parse_jwt', { jwt });
    },

    createRevocableCredential(createOptions: Record<string, unknown>): Promise<unknown> {
      return callTool('vc_create_revocable_credential', {
        options: withoutFunctionValues(createOptions),
      });
    },

    revokeCredential(revokeOptions: Record<string, unknown>): Promise<unknown> {
      return callTool('vc_revoke_credential', {
        options: withoutFunctionValues(revokeOptions),
      });
    },

    checkCredentialStatus(
      statusOptions: Record<string, unknown>,
    ): Promise<{ revoked: boolean; suspended: boolean }> {
      return callTool('vc_check_credential_status', { options: statusOptions }) as Promise<{
        revoked: boolean;
        suspended: boolean;
      }>;
    },

    EdDsaSigner(): never {
      throw new Error(
        '[agents] id-sdk-mcp does not expose raw EdDSA signer functions. ' +
          'Use vc.signCredential through the MCP session instead.',
      );
    },
  };

  const did = {
    resolve(didUrl: string) {
      return callTool('did_resolve', { didUrl }) as Promise<{ didDocument: unknown; didResolutionMetadata: unknown }>;
    },

    create(createOptions: Record<string, unknown> = {}): Promise<unknown> {
      return callTool('did_create', createOptions);
    },
  };

  return {
    connectedDid: options.connectedDid ?? '',
    agent: {
      kind: 'id-sdk-mcp',
      callTool,
    },
    vc,
    did,
    callTool,
    close,
  };
}

/**
 * Optional vendor deps that ship under `optionalDependencies` so the main
 * package still installs on platforms where their native build steps fail.
 * If the MCP server fails to start, the most likely culprit is one of these
 * being absent — we surface that in the thrown error so consumers get a
 * pointed message instead of a raw `ERR_MODULE_NOT_FOUND`.
 */
const OPTIONAL_VENDOR_DEPS: Array<{ name: string; feature: string }> = [
  { name: 'level', feature: 'DWN local storage' },
  { name: '@mattrglobal/bbs-signatures', feature: 'BBS+ credential proofs' },
];

function describeMissingOptionalDeps(serverPath: string): string[] {
  const missing: string[] = [];
  let probe: ReturnType<typeof createRequire>;
  try {
    probe = createRequire(serverPath);
  } catch {
    return missing;
  }

  for (const dep of OPTIONAL_VENDOR_DEPS) {
    try {
      probe.resolve(dep.name);
    } catch {
      missing.push(`${dep.name} (${dep.feature})`);
    }
  }

  return missing;
}

/**
 * Start an id-sdk-mcp server over stdio, call `connect`, and return an
 * `IdSdkInstance`-compatible adapter.
 */
export async function connectIdSdkMcp(
  options: IdSdkMcpClientOptions = {},
): Promise<McpBackedIdSdkInstance> {
  const serverPath = resolveVendoredIdSdkMcpServerPath(options.cwd);
  const transport = new StdioClientTransport({
    command: options.command ?? 'node',
    args: options.args ?? [serverPath],
    cwd: options.cwd,
    env: options.env,
    stderr: options.stderr ?? 'inherit',
  });
  const client = new Client({
    name: 'agents-id-sdk-mcp-client',
    version: '0.1.0',
  });

  try {
    await client.connect(transport);
  } catch (err) {
    const missing = describeMissingOptionalDeps(serverPath);
    if (missing.length > 0) {
      const message =
        '[agents] id-sdk-mcp server failed to start. ' +
        `Missing optional dependencies: ${missing.join(', ')}. ` +
        'Install them manually if you need the corresponding features ' +
        '(they are listed under optionalDependencies because their native ' +
        'build can fail on some platforms).';
      throw new Error(message, { cause: err });
    }
    throw err;
  }

  const callTool: IdSdkMcpToolCaller = async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    return parseMcpToolResult(result);
  };

  let connectedDid = options.connect?.connectedDid ?? '';
  if (options.connect) {
    const connectResult = await callTool('connect', options.connect as Record<string, unknown>);
    if (connectResult && typeof connectResult === 'object' && 'did' in connectResult) {
      connectedDid = String((connectResult as { did?: unknown }).did ?? connectedDid);
    }
  }

  return createIdSdkMcpAdapter(callTool, {
    connectedDid,
    close: () => client.close(),
  });
}
