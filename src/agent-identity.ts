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
 * AgentIdentity — SQL-free identity, authentication, and agent management.
 *
 * Manages DID generation, credential issuance, agent registration, OIDC
 * authentication, audit logging, and revocation without any pg.Pool dependency.
 * Non-SQL consumers can use the full identity layer without Postgres.
 *
 * AgentScope composes an AgentIdentity instance (not extends) to keep the
 * SQL/identity boundary explicit. `_createWithInternals()` returns
 * [instance, internals] so AgentScope.create() can wire the ScopeEngine
 * without those fields being public API.
 *
 * Storage lifecycle is owned by the caller, not AgentIdentity — prevents
 * double-close bugs when AgentScope owns the storage.
 *
 * @module
 */

import { inspect } from 'node:util';
import { asMasterKey, type MasterKey } from './crypto/master-key.js';
import { REDACTED_MASTER_KEY } from './crypto/redact.js';
import { VcVerifier, decodeJwt } from './vc-verifier.js';
import type { StorageBackend } from './storage/types.js';
import { AuthUnavailableError } from './errors.js';
import { AuditLogger } from './audit-logger.js';
import type { Logger } from './logger.js';
import { getLogger } from './logger.js';
import {
  createAgent,
  restoreAgents,
  createMockSession,
  createOidcSession,
  generateDidKey,
  issueDelegatedCredential,
} from './auth/index.js';
import { AbaxxOneOidcProvider } from './auth/abaxx-one.js';
import { createSessionFromDid } from './auth/session-factory.js';
import type { ScopeCeiling } from './auth/ceiling.js';
import { expiresInToMs } from './config.js';
import type {
  AuthOptions,
  AuthenticatedSession,
  CreateAgentOptions,
  RegisteredAgent,
  DelegateCredentialOptions,
  IdSdkInstance,
  AuditRecord,
  VerificationResult,
} from './types.js';

// ─── Config & Injection Types ──────────────────────────────────────────────────

/**
 * Identity-relevant subset of AgentScopeConfig. Excludes SQL-only fields
 * (`database`, `encryption`, `scopeMode`). Non-SQL consumers use this directly.
 */
export interface AgentIdentityConfig {
  /** AbaxxOne enterprise OIDC provider. Optional — see AgentScopeConfig.abaxxOne. */
  abaxxOne?: {
    tenantUrl: string;
    clientId: string;
    clientSecret?: string;
  };
  /** Generic OIDC provider configuration. */
  oidc?: {
    issuerUrl: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    scopes?: string[];
  };
  audit?: {
    enabled?: boolean;
  };
  credential?: {
    maxTtl?: string;
    clockSkew?: string;
  };
  did?: {
    resolverCacheTtl?: string;
  };
  log?: {
    level?: 'debug' | 'info' | 'warn' | 'error';
  };
  /**
   * Org boundary configuration. See AgentScopeConfig.orgBoundary for full docs.
   */
  orgBoundary?: {
    extraConsumerDomains?: readonly string[];
  };
  /**
   * Keystore configuration. See AgentScopeConfig.keystore for full docs.
   */
  keystore?: {
    path?: string;
  };
  delegation?: {
    maxDepth?: number; // default: 2 (human→agent→worker)
  };
  /**
   * Dev-mode opt-in. See AgentScopeConfig.devMode for full docs.
   * NOT a security gate — NODE_ENV is the runtime guard.
   */
  devMode?: boolean;
}

/** Runtime-owned dependencies for AgentIdentity. Both `storage` and `masterKey` are required. */
export interface AgentIdentityInjections {
  /** REQUIRED — storage backend for agents, audit, revocation, sessions, context. */
  storage: StorageBackend;
  /** REQUIRED — 32-byte master encryption key (branded MasterKey). */
  masterKey: MasterKey;
  /** Optional platform identity handle for full DID/VC capabilities. */
  sdk?: IdSdkInstance;
  /** Optional persistent server identity. Without it, an ephemeral did:key is generated. */
  serverIdentity?: { did: string; publicKey: Uint8Array };
  /** Optional diagnostic logger. Defaults to stderr in the library's existing format. */
  logger?: Logger;
}

/** Internal wiring exposed to AgentScope via the factory-tuple. NOT public API. */
interface AgentIdentityInternals {
  storage: StorageBackend;
  verifier: VcVerifier;
  auditLogger: AuditLogger;
  agentsMap: Map<string, RegisteredAgent>;
  verifierDid: string;
}

// ─── AgentIdentity Class ───────────────────────────────────────────────────────

export class AgentIdentity {
  private config: AgentIdentityConfig;
  private storage: StorageBackend;
  private verifier: VcVerifier;
  private auditLogger: AuditLogger;
  private agents: Map<string, RegisteredAgent> = new Map();
  private masterKey: MasterKey;
  private sdk?: IdSdkInstance;
  private closed = false;
  readonly verifierDid: string;
  private _verifierPublicKey: Uint8Array;
  private abaxxOneProvider?: AbaxxOneOidcProvider;
  readonly logger: Logger;

  private constructor(opts: {
    config: AgentIdentityConfig;
    storage: StorageBackend;
    verifier: VcVerifier;
    auditLogger: AuditLogger;
    masterKey: MasterKey;
    sdk?: IdSdkInstance;
    serverIdentity: { did: string; publicKey: Uint8Array };
    logger: Logger;
  }) {
    this.config = opts.config;
    this.storage = opts.storage;
    this.verifier = opts.verifier;
    this.auditLogger = opts.auditLogger;
    // Copy on intake so close() can zero our own memory without mutating the caller's buffer.
    this.masterKey = asMasterKey(Buffer.from(opts.masterKey));
    this.sdk = opts.sdk;
    this.verifierDid = opts.serverIdentity.did;
    this._verifierPublicKey = opts.serverIdentity.publicKey;
    this.logger = opts.logger;
    opts.verifier.registerKey(opts.serverIdentity.did, opts.serverIdentity.publicKey);
  }

  // ─── Static Factories ──────────────────────────────────────────────────────

  /**
   * Public factory for standalone (non-AgentScope) consumers.
   * The caller owns the storage lifecycle.
   */
  static async create(
    config: AgentIdentityConfig,
    injections: AgentIdentityInjections,
  ): Promise<AgentIdentity> {
    const [instance] = await AgentIdentity._createWithInternals(config, injections);
    return instance;
  }

  /**
   * Returns [instance, internals] so AgentScope.create() can wire the ScopeEngine.
   * NOT public API — AgentScope is the only intended consumer.
   */
  static async _createWithInternals(
    config: AgentIdentityConfig,
    injections: AgentIdentityInjections,
  ): Promise<[AgentIdentity, AgentIdentityInternals]> {
    const {
      storage,
      masterKey,
      sdk,
      serverIdentity: injectedIdentity,
      logger: injectedLogger,
    } = injections;
    const logger = getLogger(injectedLogger);

    // 1. Build VcVerifier
    const verifier = new VcVerifier({
      clockSkew: config.credential?.clockSkew,
      resolverCacheTtl: config.did?.resolverCacheTtl,
      sdk,
      revocationStore: storage.revocation,
    });

    // 2. Build AuditLogger (auditStore from storage — no pool dependency)
    const auditLogger = new AuditLogger({
      auditStore: storage.audit,
      enabled: config.audit?.enabled,
    });

    // 3. Generate or accept server identity
    const identity = injectedIdentity ?? generateDidKey();

    // 4. Build instance
    const instance = new AgentIdentity({
      config,
      storage,
      verifier,
      auditLogger,
      masterKey,
      sdk,
      serverIdentity: identity,
      logger,
    });

    // 5. Restore agents from storage — returns { schemaMissing: true } when the table doesn't exist yet.
    const restored = await restoreAgents(storage.agents, masterKey, verifier, logger);
    if (!('schemaMissing' in restored)) {
      for (const [did, agent] of restored) {
        instance.agents.set(did, agent);
      }
    } else {
      logger.warn(
        '[agents] Agents schema not initialized — the next operation will fail with ' +
          `'relation "agents" does not exist'. Run: agents init --db <url>`,
        {
          event: 'restore_agents_schema_missing',
          table: 'agents',
          nextStep: 'agents init --db <url>',
        },
      );
    }

    // 6. Return tuple
    const internals: AgentIdentityInternals = {
      storage,
      verifier,
      auditLogger,
      agentsMap: instance.agents,
      verifierDid: instance.verifierDid,
    };

    return [instance, internals];
  }

  // ─── Identity Methods ──────────────────────────────────────────────────────

  /** Set the platform identity handle after creation (e.g., when MCP connect initializes async). */
  setSdk(sdk: IdSdkInstance): void {
    this.assertOpen();
    this.sdk = sdk;
    this.verifier.setSdk(sdk);
  }

  /** Merge config.credential.maxTtl into a caller-supplied ceiling. */
  private effectiveCeiling(callerCeiling?: ScopeCeiling): ScopeCeiling | undefined {
    const configMaxTtl = this.config.credential?.maxTtl;
    if (!configMaxTtl && !callerCeiling) return undefined;
    if (!configMaxTtl) return callerCeiling;

    const configMs = expiresInToMs(configMaxTtl);

    if (callerCeiling) {
      return {
        ...callerCeiling,
        credentialMaxTtlMs: Math.min(configMs, callerCeiling.credentialMaxTtlMs ?? Infinity),
      };
    }

    return {
      columns: ['*'],
      actions: ['*'],
      source: 'mock-unrestricted' as const,
      resolvedFrom: [],
      credentialMaxTtlMs: configMs,
    };
  }

  /**
   * Authenticate via OIDC or mock (dev/test only).
   * Paths: mockHumanDid (dev/test), oidcIdentity (pre-obtained), or AbaxxOne redirect.
   */
  async authenticate(options: AuthOptions = {}): Promise<AuthenticatedSession> {
    this.assertOpen();
    if (options.mockHumanDid) {
      // NODE_ENV gate is independent of devMode config — defense in depth.
      const env = (process.env.NODE_ENV ?? '').toLowerCase();
      if (env !== 'development' && env !== 'test') {
        throw new Error(
          'Mock authentication is only allowed when NODE_ENV=development or NODE_ENV=test. ' +
            'Set NODE_ENV appropriately, or use real OIDC authentication.',
        );
      }
      return createMockSession(
        this.verifier,
        options.mockHumanDid,
        this.sdk,
        this.effectiveCeiling(options.scopeCeiling),
      );
    }

    if (options.oidcIdentity) {
      return createOidcSession(
        this.verifier,
        options.oidcIdentity,
        this.sdk,
        this.effectiveCeiling(options.scopeCeiling),
        this.logger,
      );
    }

    if (this.config.abaxxOne) {
      const provider = this.ensureAbaxxOneProvider(options.redirectUri);
      const { url } = await provider.buildAuthorizationUrl();
      throw new AuthUnavailableError(`OIDC flow requires browser redirect to: ${url}`);
    }

    throw new Error(
      'No authentication method configured. Provide one of: ' +
        'mockHumanDid (dev/test), oidcIdentity (from completed OAuth flow), ' +
        'or configure abaxxOne/oidc in AgentIdentityConfig.',
    );
  }

  /**
   * Complete OIDC authentication after receiving the authorization code callback.
   *
   * The `state` parameter is validated against the provider's internal
   * PendingFlowStore opened by the matching `authenticate()` call.
   * Mismatch, expiry, unknown state, or PKCE verifier mismatch raises
   * `AuthUnavailableError` before any network call.
   */
  async completeAuthentication(
    authorizationCode: string,
    state: string,
    codeVerifier: string,
  ): Promise<AuthenticatedSession> {
    this.assertOpen();
    if (!this.config.abaxxOne) {
      throw new Error(
        'completeAuthentication() requires abaxxOne config. ' +
          'Generic OIDC completion is handled by GenericOidcProvider.exchangeCode() directly.',
      );
    }
    const provider = this.ensureAbaxxOneProvider();
    const identity = await provider.exchangeCode(authorizationCode, state, codeVerifier);
    return createSessionFromDid(
      identity.humanDid,
      identity.email,
      this.verifier,
      this.sdk,
      undefined,
      undefined,
      this.effectiveCeiling(),
      undefined,
      this.logger,
    );
  }

  async createAgent(options: CreateAgentOptions): Promise<RegisteredAgent> {
    this.assertOpen();
    if (!options.name || typeof options.name !== 'string' || options.name.trim() === '') {
      throw new Error(
        'createAgent() requires name. Pass a non-empty string identifying the agent.',
      );
    }
    if (!options.ownerDid) {
      throw new Error(
        "createAgent() requires ownerDid. Pass the authenticated human's DID " +
          '(authSession.humanDid) to bind the agent to its owner.',
      );
    }
    const agent = await createAgent(
      this.storage.agents,
      options as CreateAgentOptions & { ownerDid: string },
      this.verifier,
      this.sdk,
      this.masterKey,
    );
    this.agents.set(agent.did, agent);
    return agent;
  }

  /**
   * Delegate a credential subset from one agent to another.
   * Columns and actions must be subsets of the source credential; TTL cannot exceed it.
   * The source credential is verified before its claims are trusted.
   */
  async delegateCredential(
    sourceAgentDid: string,
    sourceCredential: string,
    options: DelegateCredentialOptions,
  ): Promise<string> {
    this.assertOpen();
    const agent = this.agents.get(sourceAgentDid);
    if (!agent) {
      throw new Error(
        `Agent ${sourceAgentDid} not found. Create the agent first with createAgent().`,
      );
    }

    const verifyResult = await this.verifier.verify(sourceCredential, {
      expectedSubject: sourceAgentDid,
    });
    if (!verifyResult.valid) {
      throw new Error(
        `Source credential verification failed: ${verifyResult.status} — ${verifyResult.error ?? 'unknown error'}. ` +
          `Cannot delegate from an unverified credential.`,
      );
    }

    const ownerDid = agent.ownerDid;
    if (verifyResult.credential!.issuer !== ownerDid) {
      throw new Error(
        `Source credential issuer ${verifyResult.credential!.issuer} is not the registered owner ` +
          `(${ownerDid}) of agent ${sourceAgentDid}. Cannot delegate.`,
      );
    }

    const sourceScope = verifyResult.credential!.scope;
    if (!sourceScope?.columns || !sourceScope?.actions) {
      throw new Error('Source credential has no scope — cannot delegate.');
    }

    const decoded = decodeJwt(sourceCredential);
    const sourceJti = decoded.payload.jti ?? 'unknown';
    const maxExpSeconds = decoded.payload.exp;

    return issueDelegatedCredential(
      sourceAgentDid,
      agent.signer,
      sourceCredential,
      sourceJti,
      sourceScope,
      {
        targetAgent: options.targetAgent,
        columns: options.columns,
        actions: options.actions,
        expiresIn: options.expiresIn,
        maxExpSeconds,
        operatorMaxDepth: this.config.delegation?.maxDepth ?? 2,
        metadata: options.metadata,
      },
    );
  }

  /** Verify an audit record's signature. */
  async verify(auditRecord: AuditRecord): Promise<VerificationResult> {
    this.assertOpen();
    const publicKey = await this.verifier.resolvePublicKey(auditRecord.agentDid);
    const valid = await this.auditLogger.verifyRecord(auditRecord, publicKey);
    return {
      valid,
      status: valid ? 'VALID' : 'INVALID_SIGNATURE',
      error: valid ? undefined : 'Audit record signature verification failed',
    };
  }

  /** List registered agents with optional filtering. */
  async listAgents(
    filter: { ownerDid?: string; limit?: number } = {},
  ): Promise<Array<{ did: string; name: string; ownerDid: string; createdAt: string }>> {
    this.assertOpen();
    const records = await this.storage.agents.list({
      ownerDid: filter.ownerDid,
      limit: filter.limit,
    });
    return records.map((r) => ({
      did: r.did,
      name: r.name,
      ownerDid: r.ownerDid,
      createdAt: r.createdAt,
    }));
  }

  /**
   * Returns agent count, audit record count, and in-memory agent count.
   * Does not include `encryptedColumns` or `scopeMode` — AgentScope.getServerStatus() merges those.
   */
  async getStatus(): Promise<{
    agentCount: number;
    auditRecordCount: number;
    inMemoryAgents: number;
  }> {
    this.assertOpen();
    const [agentCount, auditRecordCount] = await Promise.all([
      this.storage.agents.count(),
      this.storage.audit.count(),
    ]);

    return {
      agentCount,
      auditRecordCount,
      inMemoryAgents: this.agents.size,
    };
  }

  /**
   * Delete revocation records whose underlying credential has already expired.
   * Delegates to `storage.revocation.pruneExpired()`. When `cutoff` is omitted,
   * each backend applies its own default (typically now - 30 days).
   */
  async pruneRevocations(cutoff?: Date): Promise<number> {
    this.assertOpen();
    return this.storage.revocation.pruneExpired(cutoff);
  }

  private ensureAbaxxOneProvider(redirectUri?: string): AbaxxOneOidcProvider {
    if (!this.config.abaxxOne) {
      throw new Error('AbaxxOne OIDC not configured');
    }
    if (!this.abaxxOneProvider) {
      this.abaxxOneProvider = new AbaxxOneOidcProvider({
        tenantUrl: this.config.abaxxOne.tenantUrl,
        clientId: this.config.abaxxOne.clientId,
        clientSecret: this.config.abaxxOne.clientSecret,
        redirectUri,
      });
    }
    return this.abaxxOneProvider;
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('AgentIdentity has been closed');
  }

  close(): void {
    this.closed = true;
    this.masterKey.fill(0);
  }

  // ─── Accessors for demo/testing ──────────────────────────────────────────

  get verifierInstance(): VcVerifier {
    return this.verifier;
  }

  get auditLoggerInstance(): AuditLogger {
    return this.auditLogger;
  }

  // ─── Serialization ───────────────────────────────────────────────────────

  /** Serialise a redacted snapshot — prevents master key from appearing in logs or JSON. */
  toJSON(): {
    verifierDid: string;
    masterKey: string;
    sdk: string;
  } {
    return {
      verifierDid: this.verifierDid,
      masterKey: REDACTED_MASTER_KEY,
      sdk: this.sdk ? '[SDK]' : '[none]',
    };
  }

  /** Custom util.inspect() representation. Delegates to toJSON(). */
  [inspect.custom](): ReturnType<AgentIdentity['toJSON']> {
    return this.toJSON();
  }
}
