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
 * Host extensions. An extension adds tools and a lifecycle to the MCP host without the library
 * knowing what it does. The host calls `attach` once the scope and the session exist, registers
 * the tools it returns on every MCP server it creates, starts it before the transport accepts
 * clients, and stops it at shutdown.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuditLogger } from '#audit/logger.js';
import type { MasterKey } from '#crypto/master-key.js';
import type { TrustAnchorStore } from '#discovery/trust-anchor.js';
import type { ServerIdentity } from '#identity/server-identity.js';
import type { Logger } from '#observability/logger.js';
import type { AuthenticatedSession, RegisteredAgent } from '#types/auth.js';

/** What the MCP server applies from an extension: its tools and its agent-created hook. */
export interface McpServerExtension {
  /** Registers the extension's tools. Called once per MCP server instance. */
  registerTools?(server: McpServer): void;
  /** Called after an agent is created through the host's tools. A throw or a rejection is logged. */
  onAgentCreated?(agent: { did: string }): void | Promise<void>;
}

/** What an attached extension hands back to the host. */
export interface McpHostAttachment extends McpServerExtension {
  /** Runs before the transport accepts clients. A rejection stops the host with exit code 1. */
  start?(): Promise<void>;
  /** Runs once at shutdown. Failures are logged, never thrown. */
  stop?(): Promise<void>;
}

/** The agents registered on the host, with their signers. */
export interface McpHostAgents {
  getRegisteredAgent(did: string): RegisteredAgent | undefined;
  listRegisteredAgents(): RegisteredAgent[];
}

/** The persistent server identity as extensions see it: no keystore. */
export interface McpHostIdentity {
  serverIdentity: ServerIdentity;
  trustAnchors: TrustAnchorStore;
}

/**
 * Where the host keeps its data. `postgres` is the default backend on the connection string the
 * host was started with; `injected` is a storage backend the embedder passed in, which the host
 * cannot describe further.
 */
export type McpHostDatabase = { kind: 'postgres'; connectionString: string } | { kind: 'injected' };

/** What an extension can reach: the smallest set the host's own tools need. */
export interface McpHostExtensionContext {
  agents: McpHostAgents;
  /** The instance audit logger, so an extension's records join the same chain. */
  auditLogger: AuditLogger;
  session: AuthenticatedSession;
  masterKey: MasterKey;
  /** The persistent server identity, or null when the host runs without one. */
  identity: McpHostIdentity | null;
  database: McpHostDatabase;
  devMode: boolean;
  logger: Logger;
  /** Writes one line to the host log (stderr). */
  log(message: string): void;
}

export interface McpHostExtension {
  readonly name: string;
  /** True when the extension needs the persistent server identity to be loaded. */
  readonly needsHostIdentity?: boolean;
  /** Returns what the host wires in, or null when the extension stays off. */
  attach(context: McpHostExtensionContext): Promise<McpHostAttachment | null>;
}
