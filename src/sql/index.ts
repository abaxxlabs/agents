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
 * PostgreSQL-specific surface: AgentScope, ScopeEngine, and pool-dependent
 * column-key management. Non-SQL consumers import from `@abaxxlabs/agents`
 * to avoid pulling in pg or libpg-query.
 *
 * @example
 * ```typescript
 * import { AgentScope } from '@abaxxlabs/agents/sql';
 * import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
 *
 * const scope = await AgentScope.create(
 *   { database: { connectionString: process.env.DATABASE_URL! } },
 *   { masterKey: resolveMasterKeyFromEnv() },
 * );
 * ```
 *
 * @module
 */

import pg from 'pg';
import { inspect } from 'node:util';
import { loadConfig, parseDuration } from '../config.js';
import { loadColumnKeys } from './column-keys.js';
import { VcVerifier } from '../vc-verifier.js';
import { PostgresStorageBackend } from '../storage/postgres/index.js';
import type { StorageBackend } from '../storage/types.js';
import { deriveSessionMacKey } from '../storage/envelope-mac.js';
import { AuditLogger } from '../audit-logger.js';
import { ScopeEngine } from './scope-engine.js';
import { AgentIdentity } from '../agent-identity.js';
import type { AgentIdentityConfig } from '../agent-identity.js';
import { DbConnectionFailedError } from '../errors/index.js';
import { getLogger } from '../logger.js';
import type { AgentScopeConfig, ScopeMode } from '../types/config.js';
import type {
  AuthOptions,
  AuthenticatedSession,
  CreateAgentOptions,
  RegisteredAgent,
} from '../types/auth.js';
import type { DelegateCredentialOptions } from '../types/credential.js';
import type { IdSdkInstance } from '../types/id-sdk.js';
import type { AuditRecord } from '../types/audit.js';
import type { VerificationResult } from '../types/verification.js';
import type {
  AgentScopeInjections,
  AgentScopeInstance,
  QueryOptions,
  ScopedResult,
} from './types.js';

const { Pool } = pg;

/**
 * AgentScope — PostgreSQL composition wrapper around AgentIdentity.
 *
 * Owns the pg.Pool, ScopeEngine, column keys, and encrypted-columns set.
 * All identity/auth/agent management delegates to the composed AgentIdentity.
 */
export class AgentScope implements AgentScopeInstance {
  /** Composed identity layer — owns DID, auth, agents, audit, revocation. */
  private identity: AgentIdentity;
  private pool: pg.Pool;
  private config: AgentScopeConfig;
  private engine: ScopeEngine;
  private columnKeys: Map<string, Buffer>;
  private encryptedColumns: Set<string>;
  /** Storage backend. Source of truth for revocation, agents, audit, context, sessions. */
  private storage: StorageBackend;
  /** True when AgentScope built the storage backend; close() will end it. See DECISIONS.md D-002. */
  private ownsStorage: boolean;
  /** True when AgentScope built the pg.Pool; close() will end it. See DECISIONS.md D-002. */
  private ownsPool: boolean;

  /**
   * The server instance's own DID, used as the audience for Verifiable Presentations.
   * Generated at construction unless a persistent identity is supplied via `injections.serverIdentity`.
   * See DECISIONS.md D-004.
   */
  get verifierDid(): string {
    return this.identity.verifierDid;
  }

  get credentialMaxTtlMs(): number {
    return parseDuration(this.config.credential?.maxTtl ?? '24h');
  }

  private constructor(opts: {
    identity: AgentIdentity;
    pool: pg.Pool;
    config: AgentScopeConfig;
    engine: ScopeEngine;
    columnKeys: Map<string, Buffer>;
    encryptedColumns: Set<string>;
    storage: StorageBackend;
    ownsStorage: boolean;
    ownsPool: boolean;
  }) {
    this.identity = opts.identity;
    this.pool = opts.pool;
    this.config = opts.config;
    this.engine = opts.engine;
    this.columnKeys = opts.columnKeys;
    this.encryptedColumns = opts.encryptedColumns;
    this.storage = opts.storage;
    this.ownsStorage = opts.ownsStorage;
    this.ownsPool = opts.ownsPool;
  }

  /**
   * Create and initialize an AgentScope instance.
   *
   * `injections.masterKey` is required — no env-var fallback. Source via
   * `resolveMasterKeyFromEnv()` from `@abaxxlabs/agents/bootstrap` or your own KMS.
   *
   * When `injections.storage` is omitted, a `PostgresStorageBackend` is built and
   * owned by AgentScope but NOT `.initialize()`d — migrations are a deployment concern.
   * Caller-supplied `pool` and `storage` are not closed by `AgentScope.close()`.
   */
  private static maskConnectionCredentials(cs: string): string {
    const proto = cs.indexOf('//');
    if (proto === -1) return cs;
    const at = cs.indexOf('@', proto + 2);
    if (at === -1) return cs;
    return cs.slice(0, proto + 2) + '***' + cs.slice(at);
  }

  static async create(
    configInput: AgentScopeConfig | string,
    injections: AgentScopeInjections,
  ): Promise<AgentScope> {
    const config =
      typeof configInput === 'string' ? loadConfig(configInput) : loadConfig(configInput);

    // ── Pool setup ─────────────────────────────────────────────────────────
    const ownsPool = injections.pool === undefined;
    const pool =
      injections.pool ??
      new Pool({
        connectionString: config.database.connectionString,
        max: config.database.poolSize ?? 10,
      });

    try {
      await pool.query('SELECT 1');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new DbConnectionFailedError(
        AgentScope.maskConnectionCredentials(config.database.connectionString),
        message,
      );
    }

    // ── Storage setup ──────────────────────────────────────────────────────
    const masterKey = injections.masterKey;
    const logger = getLogger(injections.logger);

    let storage: StorageBackend;
    let ownsStorage: boolean;
    if (injections.storage) {
      storage = injections.storage;
      ownsStorage = false;
    } else {
      const sessionMacKey = deriveSessionMacKey(masterKey);
      storage = PostgresStorageBackend.fromPool(pool, /* ownsPool */ false, {
        sessionMacKey,
        logger,
      });
      ownsStorage = true;
    }

    // ── Column keys (SQL-specific) ─────────────────────────────────────────
    const loadedColumnKeys = await loadColumnKeys(pool, masterKey, logger);
    const columnKeys: Map<string, Buffer> =
      'schemaMissing' in loadedColumnKeys ? new Map() : loadedColumnKeys;
    const encryptedColumns = new Set<string>(columnKeys.keys());

    // ── AgentIdentity creation via factory-tuple ───────────────────────────
    //    Extract identity-relevant config subset for AgentIdentity.
    const identityConfig: AgentIdentityConfig = {
      abaxxOne: config.abaxxOne,
      oidc: config.oidc,
      audit: config.audit,
      credential: config.credential,
      did: config.did,
      log: config.log,
      orgBoundary: config.orgBoundary,
      keystore: config.keystore,
      devMode: config.devMode,
    };

    const [identity, internals] = await AgentIdentity._createWithInternals(identityConfig, {
      storage,
      masterKey,
      sdk: injections.sdk,
      serverIdentity: injections.serverIdentity,
      logger,
    });

    // ── ScopeEngine (SQL-specific) ─────────────────────────────────────────
    const engine = new ScopeEngine({
      pool,
      verifier: internals.verifier,
      auditLogger: internals.auditLogger,
      columnKeys,
      encryptedColumns,
      agents: internals.agentsMap,
      verifierDid: internals.verifierDid,
      scopeMode: config.scopeMode,
      agentStore: storage.agents,
    });

    return new AgentScope({
      identity,
      pool,
      config,
      engine,
      columnKeys,
      encryptedColumns,
      storage,
      ownsStorage,
      ownsPool,
    });
  }

  // ─── Identity method delegation ────────────────────────────────────────────

  /** Set the platform identity handle after creation (e.g., when MCP connect initializes async). */
  setSdk(sdk: IdSdkInstance): void {
    this.identity.setSdk(sdk);
  }

  /**
   * Authenticate a human via OIDC (AbaxxOne or generic provider), or mock for demo/testing.
   *
   * Three paths:
   *   1. mockHumanDid — dev/test only. Creates a session with a synthetic DID.
   *   2. oidcIdentity — creates a session from a pre-obtained OIDC identity
   *      (the web app handles the OAuth flow; the SDK handles identity → credential).
   *   3. AbaxxOne redirect — builds an authorization URL for browser redirect.
   */
  async authenticate(options: AuthOptions = {}): Promise<AuthenticatedSession> {
    return this.identity.authenticate(options);
  }

  /**
   * Complete OIDC authentication after receiving the authorization code callback.
   *
   * The `state` parameter is required and is validated against the provider's
   * PendingFlowStore opened by the matching `authenticate()` call. Throws
   * `AuthUnavailableError` on any state mismatch, expiry, or PKCE verifier
   * mismatch — before any network exchange.
   */
  async completeAuthentication(
    authorizationCode: string,
    state: string,
    codeVerifier: string,
  ): Promise<AuthenticatedSession> {
    return this.identity.completeAuthentication(authorizationCode, state, codeVerifier);
  }

  /**
   * Create a new agent identity (DID + key pair).
   *
   * `ownerDid` is required — pass the authenticated human's DID. See DECISIONS.md D-009.
   */
  async createAgent(options: CreateAgentOptions): Promise<RegisteredAgent> {
    return this.identity.createAgent(options);
  }

  /**
   * Delegate a credential from one agent to another.
   *
   * Enables supervisor/worker patterns: a supervisor agent delegates a SUBSET of
   * its own scope to a worker agent.
   */
  async delegateCredential(
    sourceAgentDid: string,
    sourceCredential: string,
    options: DelegateCredentialOptions,
  ): Promise<string> {
    return this.identity.delegateCredential(sourceAgentDid, sourceCredential, options);
  }

  /** Verify an audit record's signature. */
  async verify(auditRecord: AuditRecord): Promise<VerificationResult> {
    return this.identity.verify(auditRecord);
  }

  /** List registered agents with optional filtering. */
  async listAgents(
    filter: { ownerDid?: string; limit?: number } = {},
  ): Promise<Array<{ did: string; name: string; ownerDid: string; createdAt: string }>> {
    return this.identity.listAgents(filter);
  }

  /**
   * Delete revocation records whose underlying credential has already expired.
   * Delegates to identity, which delegates to `storage.revocation.pruneExpired()`.
   */
  async pruneRevocations(cutoff?: Date): Promise<number> {
    return this.identity.pruneRevocations(cutoff);
  }

  // ─── SQL-specific methods (stay on AgentScope) ─────────────────────────────

  /** Execute a scoped query through the middleware. */
  async query(options: QueryOptions): Promise<ScopedResult> {
    return this.engine.query(options);
  }

  /**
   * Get server status: agent count, audit record count, encrypted columns.
   *
   * Merges identity-level status (agentCount, auditRecordCount, inMemoryAgents)
   * with SQL-specific field (encryptedColumns).
   */
  async getServerStatus(): Promise<{
    agentCount: number;
    auditRecordCount: number;
    encryptedColumns: string[];
    inMemoryAgents: number;
    scopeMode: ScopeMode;
  }> {
    const status = await this.identity.getStatus();
    return {
      ...status,
      encryptedColumns: Array.from(this.encryptedColumns),
      scopeMode: this.config.scopeMode ?? 'projection',
    };
  }

  /**
   * Close storage (if owned), end the pool (if owned), and zero the master key.
   * Order: master key → storage (may query pool) → pool.
   */
  async close(): Promise<void> {
    // Zero master key via identity
    this.identity.close();
    // Close storage if owned (may run final queries against pool)
    if (this.ownsStorage) {
      await this.storage.close();
    }
    // Close pool if owned
    if (this.ownsPool) {
      await this.pool.end();
    }
  }

  /** Serialise a redacted snapshot for logs. MasterKey brand prevents accidental leaks. */
  toJSON(): {
    verifierDid: string;
    encryptedColumns: string[];
    masterKey: string;
    sdk: string;
    ownsStorage: boolean;
    ownsPool: boolean;
  } {
    return {
      ...this.identity.toJSON(),
      encryptedColumns: Array.from(this.encryptedColumns),
      ownsStorage: this.ownsStorage,
      ownsPool: this.ownsPool,
    };
  }

  /** Custom util.inspect() representation. Delegates to toJSON() for a single source of truth. */
  [inspect.custom](): ReturnType<AgentScope['toJSON']> {
    return this.toJSON();
  }

  // ─── Accessors for demo/testing ──────────────────────────────

  get verifierInstance(): VcVerifier {
    return this.identity.verifierInstance;
  }

  get auditLoggerInstance(): AuditLogger {
    return this.identity.auditLoggerInstance;
  }
}

// ─── SQL-specific re-exports ──────────────────────────────────────

export type { ScopeMode } from './scope-engine.js';
export { ScopeEngine } from './scope-engine.js';

export {
  loadColumnKeys,
  registerColumn,
  encryptColumnInPlace,
  rotateColumnKey,
  rewrapColumnKey,
  verifyAllColumnKeys,
} from './column-keys.js';
export type { LoadColumnKeysResult } from './column-keys.js';

// AgentScopeConfig stays in the shared types module (pg-free).
export type { AgentScopeConfig } from '../types/config.js';

// SQL-specific types that reference pg live in sql/types.ts.
export type {
  AgentScopeInjections,
  AgentScopeInstance,
  QueryOptions,
  ScopedResult,
} from './types.js';

// Re-export all errors so instanceof checks work across subpaths.
export {
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  DidResolutionFailedError,
  AuthUnavailableError,
  DbConnectionFailedError,
  AuditWriteFailedError,
  AgentScopeError,
  QueryRejectedError,
  ScopeViolationError,
  CredentialReplayedError,
  CapabilityRequiresPaidTierError,
  ParentCredentialRequestFailedError,
  KeyRotationFailedError,
  type KeyRotationPhase,
  MasterKeyMismatchError,
  MasterKeyMissingError,
} from '../errors/index.js';
