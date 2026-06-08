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
 * Agents++ — Scope Enforcement Engine
 *
 * Orchestrates the query pipeline:
 * 1. Verify credential (vc-verifier)
 * 2. Parse scope from VC
 * 3. Execute SQL query via pg.Pool
 * 4. Decrypt in-scope columns, pass through out-of-scope as ciphertext
 * 5. Log audit record (audit/logger)
 * 6. Return ScopedResult
 */

import type { Pool } from 'pg';
import type { RegisteredAgent } from '#types/auth.js';
import type { ScopeMode } from '#types/config.js';
import type { QueryOptions, ScopedResult } from './types.js';
import type { AgentStore } from '#storage/types.js';
import { VcVerifier } from '#identity/index.js';
import { decodeJwt } from '#crypto/jwt.js';
import { decryptRow } from '#encryption/index.js';
import { AuditLogger } from '#audit/index.js';
import { createPresentation } from '#identity/index.js';
import {
  AgentScopeError,
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  QueryRejectedError,
  CredentialReplayedError,
} from '#errors/index.js';
import type { DidAliasRegistry } from '#did/alias.js';
import type { Did, TableName } from '#types/domain.js';
import { assertReadOnlyQuery, assertProjectionBoundary } from './query-policy.js';

// ScopeMode is defined in src/types/config.ts to keep the identity-only entry free
// of transitive sql/ imports. Re-exported here so consumers importing from
// @abaxxlabs/agents/sql still resolve it.
export type { ScopeMode } from '#types/config.js';

export interface ScopeEngineOptions {
  pool: Pool;
  verifier: VcVerifier;
  auditLogger: AuditLogger;
  columnKeys: Map<string, Buffer>;
  encryptedColumns: Set<string>;
  /** Map of agent DID → RegisteredAgent (for signing audit records) */
  agents: Map<string, RegisteredAgent>;
  /** Server's own DID — used as VP audience to prevent cross-server replay. */
  verifierDid: string;
  /**
   * DID alias registry for grace period DID comparison. When a user migrates
   * from did:key to did:dht, the alias registry resolves both DIDs to the
   * same identity for the owner check, delegation chain validation, and
   * issuer consistency checks. Optional — when absent, strict === is used.
   */
  didAliases?: DidAliasRegistry;
  /**
   * Controls how the projection boundary enforces column access.
   * 'projection' (default and only option): reject ANY column not in
   * credential scope.
   */
  scopeMode?: ScopeMode;
  /**
   * Agent registry store for owner-lookup fallback when the in-memory agents
   * Map misses (e.g., after process restart). Decouples ScopeEngine from
   * direct pool.query for metadata reads — pool is now used solely for
   * data-plane query execution.
   */
  agentStore: AgentStore;
}

export class ScopeEngine {
  private pool: Pool;
  private verifier: VcVerifier;
  private auditLogger: AuditLogger;
  private columnKeys: Map<string, Buffer>;
  private encryptedColumns: Set<string>;
  private agents: Map<string, RegisteredAgent>;
  private verifierDid: string;
  private didAliases?: DidAliasRegistry;
  private scopeMode: ScopeMode;
  private agentStore: AgentStore;

  constructor(options: ScopeEngineOptions) {
    this.pool = options.pool;
    this.verifier = options.verifier;
    this.auditLogger = options.auditLogger;
    this.columnKeys = options.columnKeys;
    this.encryptedColumns = options.encryptedColumns;
    this.agents = options.agents;
    this.verifierDid = options.verifierDid;
    this.didAliases = options.didAliases;
    this.agentStore = options.agentStore;
    const mode = options.scopeMode ?? 'projection';
    if (mode !== 'projection') {
      throw new Error(`Invalid scopeMode "${mode}" — must be "projection".`);
    }
    this.scopeMode = mode;
  }

  /**
   * Alias-aware DID comparison. Falls back to strict === when no alias
   * registry is configured.
   */
  private didsMatch(a: string, b: string): boolean {
    if (a === b) return true;
    return this.didAliases?.didsMatch(a, b) ?? false;
  }

  /**
   * Execute a scoped query.
   *
   * The agent presents a DID + credential JWT + SQL query.
   * The engine verifies the credential, executes the query,
   * decrypts only the columns the credential authorizes,
   * and returns everything else as ciphertext.
   */
  async query(options: QueryOptions): Promise<ScopedResult> {
    try {
      return await this._executeQuery(options);
    } catch (err) {
      // Log rejection audit from the scope engine (not server catch blocks)
      // so SDK consumers without an HTTP server still get audit trails.
      if (err instanceof AgentScopeError) {
        const rejectionAgent = this.agents.get(options.agent);
        await this.auditLogger
          .logRejection(err.message, err.code, rejectionAgent?.signer, {
            agentDid: options.agent,
            sql: options.sql,
            orgId: options.orgId,
          })
          .catch(() => {
            // Best-effort: don't let rejection audit failure mask the original error
          });
      }
      throw err;
    }
  }

  private async _executeQuery(options: QueryOptions): Promise<ScopedResult> {
    const startTime = Date.now();

    // 1. Collect all credentials (support single + multi)
    const allJwts: string[] = [];
    if (options.credential) allJwts.push(options.credential);
    if (options.credentials) allJwts.push(...options.credentials);

    if (allJwts.length === 0) {
      throw new CredentialMalformedError('No credential provided');
    }

    // 2. Verify all credentials and union scopes.
    //
    // W3C VP wrapping: raw VCs are wrapped in a Verifiable Presentation
    // before verification. This ensures replay protection applies to the
    // VP nonce (per-query, ephemeral) rather than the VC JTI (per-credential,
    // long-lived). The VC remains reusable across queries — each query
    // creates a fresh VP wrapping the same VC.
    //
    // The agent's signer is looked up from the agents map. If the agent
    // isn't registered (shouldn't happen — createAgent precedes query),
    // the raw VC is passed through for backward compatibility.
    const agent = this.agents.get(options.agent);
    const unionScope: Set<string> = new Set();
    let ownerDid = '';

    for (const jwt of allJwts) {
      let jwtToVerify = jwt;

      // Wrap raw VCs in a VP for proper replay semantics.
      // VPs (already wrapped) pass through unchanged.
      const decoded = decodeJwt(jwt);
      const vpClaim = decoded.payload.vp as { type?: string[] } | undefined;
      const isAlreadyVP = vpClaim?.type?.includes?.('VerifiablePresentation');
      if (!isAlreadyVP && options.requirePresentation) {
        throw new CredentialInvalidError(
          options.agent,
          'Remote query paths require a Verifiable Presentation signed by the agent; raw credentials are bearer tokens.',
        );
      }
      if (!isAlreadyVP && agent?.signer) {
        jwtToVerify = await createPresentation(jwt, options.agent, agent.signer, {
          audience: this.verifierDid,
        });
      }

      const result = await this.verifier.verify(jwtToVerify, {
        expectedAudience: this.verifierDid,
      });

      if (!result.valid) {
        switch (result.status) {
          case 'INVALID_SIGNATURE':
            throw new CredentialInvalidError(options.agent, result.error);
          case 'EXPIRED':
            throw new CredentialExpiredError(
              options.agent,
              result.credential?.expiresAt ?? new Date(),
            );
          case 'REVOKED':
          case 'SUSPENDED':
            throw new CredentialRevokedError(
              'unknown',
              result.credential?.issuer ?? 'unknown',
              result.status === 'SUSPENDED',
            );
          case 'UNKNOWN_ISSUER':
            throw new UnknownIssuerError(result.credential?.issuer ?? 'unknown', result.error);
          case 'REPLAYED': {
            const decoded = decodeJwt(jwt);
            throw new CredentialReplayedError(options.agent, decoded.payload.jti ?? 'unknown');
          }
          case 'WRONG_SUBJECT':
            // Credential is cryptographically valid but was issued for a different agent.
            // Distinct from INVALID_SIGNATURE — the key is correct, the binding is wrong.
            // Use CredentialInvalidError (not CredentialMalformedError) so callers debug
            // authorization, not key rotation.
            throw new CredentialInvalidError(
              options.agent,
              result.error ?? 'Credential issued for wrong agent',
            );
          case 'WRONG_AUDIENCE':
            throw new CredentialInvalidError(
              options.agent,
              result.error ?? 'VP audience does not match this server',
            );
          case 'POLICY_VIOLATION':
            throw new CredentialInvalidError(
              options.agent,
              result.error ?? 'Delegation chain exceeds maximum depth',
            );
          case 'MALFORMED':
          default:
            throw new CredentialMalformedError(result.error ?? 'Unknown error');
        }
      }

      // Verify the credential is for this agent. Uses didsMatch() because
      // during the migration grace period, agent credentials issued under
      // the old DID must still be accepted when the agent presents with its
      // new DID.
      if (!this.didsMatch(result.credential!.subject!, options.agent)) {
        throw new CredentialInvalidError(
          options.agent,
          `Credential subject ${result.credential!.subject} does not match agent ${options.agent}`,
        );
      }

      // Verify the credential issuer is the agent's registered owner.
      // The in-memory agents Map may not have the agent (e.g., after restart),
      // so fall back to the database. The guard must NOT silently pass on
      // cache miss — without the DB fallback, the owner check would skip
      // entirely whenever `agents.get()` returns undefined.
      let ownerAgent = this.agents.get(options.agent);
      if (!ownerAgent) {
        // Cache miss — load from storage layer to ensure owner binding survives restarts.
        // Uses AgentStore.findByDid() instead of direct pool.query to keep ScopeEngine
        // decoupled from SQL for metadata reads (pool is used solely for data-plane queries).
        try {
          const record = await this.agentStore.findByDid(options.agent);
          if (record) {
            ownerAgent = {
              did: record.did,
              name: record.name,
              ownerDid: record.ownerDid,
            } as RegisteredAgent;
          }
        } catch (dbErr) {
          // Fail closed. A storage error silently skipping the owner check is a
          // security downgrade — propagate so the query is rejected.
          throw new CredentialInvalidError(
            options.agent,
            `Agent owner lookup failed — ${dbErr instanceof Error ? dbErr.message : 'database error'}. Cannot verify credential issuer.`,
          );
        }
      }
      if (!ownerAgent) {
        throw new CredentialInvalidError(
          options.agent,
          `Agent ${options.agent} is not registered. Cannot verify credential issuer without a known owner binding.`,
        );
      }
      const isThisDelegated =
        result.credential!.vcTypes?.includes('DelegatedAgentScopeCredential') ?? false;

      if (!this.didsMatch(result.credential!.issuer, ownerAgent.ownerDid)) {
        // If this is a delegated credential, walk the delegation chain instead
        // of rejecting outright. A delegated credential has iss = delegator
        // agent DID (not the human owner). The chain must prove:
        // human owner → delegator agent → this credential.
        const isDelegated = isThisDelegated;
        const chain = result.credential!.delegationChain;
        if (!isDelegated || !chain || chain.length === 0) {
          throw new CredentialInvalidError(
            options.agent,
            `Credential issuer ${result.credential!.issuer} is not the registered owner of agent ${options.agent}`,
          );
        }

        // Verify the source credential in the chain. One level only — nested
        // delegation is not supported. The source VC must be:
        //   1. Cryptographically valid (signature, expiry, revocation)
        //   2. Issued by the human owner (source.issuer === ownerAgent.ownerDid)
        //   3. Issued TO the delegator (source.subject === delegated.issuer)
        const sourceJwt = chain[0];
        const sourceResult = await this.verifier.verify(sourceJwt, {
          expectedSubject: result.credential!.issuer,
        });
        if (!sourceResult.valid) {
          throw new CredentialInvalidError(
            options.agent,
            `Delegation chain invalid: source credential verification failed — ` +
              `${sourceResult.status}: ${sourceResult.error ?? 'unknown'}`,
          );
        }
        if (!this.didsMatch(sourceResult.credential!.issuer, ownerAgent.ownerDid)) {
          throw new CredentialInvalidError(
            options.agent,
            `Delegation chain invalid: source credential issuer ` +
              `${sourceResult.credential!.issuer} is not the registered owner ` +
              `(${ownerAgent.ownerDid}) of the delegating agent`,
          );
        }
      }

      // Delegated credentials cannot be unioned — combining narrow delegations
      // reconstructs wider access than any single delegation authorized.
      if (isThisDelegated && allJwts.length > 1) {
        throw new CredentialInvalidError(
          options.agent,
          `Delegated credentials cannot be combined in a scope union. ` +
            `A worker must hold a single credential listing all authorized columns; ` +
            `it cannot recombine narrow delegations to construct wider access.`,
        );
      }

      // Issuer consistency check — all credentials in a multi-VC query must
      // come from the same issuer to prevent scope union across different issuers.
      const thisIssuer = result.credential!.issuer;
      if (!ownerDid) {
        ownerDid = thisIssuer;
      } else if (!this.didsMatch(thisIssuer, ownerDid)) {
        throw new CredentialInvalidError(
          options.agent,
          `Credential issuer ${thisIssuer} does not match first credential's issuer ${ownerDid}. ` +
            `All credentials in a scope union must come from the same issuer.`,
        );
      }

      // Union scopes
      // scope is Optional on DecodedCredential (IdentityBindingCredentials carry no scope).
      // The verify() call above with no skipScopeCheck means MALFORMED is returned for
      // capability credentials missing scope — but guard defensively at the access site.
      if (!result.credential!.scope?.columns) {
        throw new CredentialMalformedError(
          'Credential missing scope.columns — cannot compute query scope',
        );
      }
      for (const col of result.credential!.scope.columns) {
        unionScope.add(col);
      }
    }

    const scopeColumns = Array.from(unionScope);

    // Validate table name — must be a safe SQL identifier (letters, digits,
    // underscores, optional schema-qualified with a single dot). Rejects
    // injection via options.table before it reaches assertProjectionBoundary
    // or decryptRow.
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/.test(options.table)) {
      throw new QueryRejectedError(options.agent, `Invalid table name: "${options.table}"`);
    }

    // Parse SQL with the real PostgreSQL parser and reject any mutation
    // statements. Catches writable CTEs, subquery mutations, and all DDL/DML —
    // no regex bypass possible.
    const agentDid = options.agent as Did;
    const table = options.table as TableName;

    await assertReadOnlyQuery(options.sql, agentDid);

    // Projection boundary — reject queries for out-of-scope columns. Runs
    // BEFORE query execution so no data touches disk for unauthorized requests.
    await assertProjectionBoundary(
      options.sql,
      table,
      unionScope,
      agentDid,
    );

    // 3. Execute SQL query (parameterized — caller must use $1, $2, etc.)
    const queryResult = await this.pool.query(options.sql, options.params);

    // 4. Table name is explicitly declared by the caller (not parsed from SQL)
    const tableName = options.table;

    // 5. Decrypt rows based on scope
    const allColumnsDecrypted: Set<string> = new Set();
    const allColumnsEncrypted: Set<string> = new Set();

    const decryptedRows = queryResult.rows.map((row) => {
      const { decrypted, columnsDecrypted, columnsEncrypted } = decryptRow(
        row as Record<string, unknown>,
        scopeColumns,
        tableName,
        this.columnKeys,
        this.encryptedColumns,
      );
      columnsDecrypted.forEach((c) => allColumnsDecrypted.add(c));
      columnsEncrypted.forEach((c) => allColumnsEncrypted.add(c));
      return decrypted;
    });

    const durationMs = Date.now() - startTime;

    // 6. Log audit record.
    // Fail closed — the agent must be registered to proceed (no silent audit skip).
    const auditAgent = this.agents.get(options.agent);
    if (!auditAgent) {
      throw new CredentialInvalidError(
        options.agent,
        `Agent ${options.agent} is not registered. Cannot create signed audit record.`,
      );
    }

    const auditRecord = await this.auditLogger.log(
      {
        agentDid: options.agent,
        ownerDid,
        credentialJwt: allJwts[0],
        sql: options.sql,
        columnsAccessed: scopeColumns,
        rowCount: decryptedRows.length,
        durationMs,
        orgId: options.orgId,
      },
      auditAgent.signer,
    );
    const auditId = auditRecord.id;

    // 7. Return scoped result
    return {
      rows: decryptedRows,
      metadata: {
        agent: options.agent,
        owner: ownerDid,
        columnsDecrypted: Array.from(allColumnsDecrypted),
        columnsEncrypted: Array.from(allColumnsEncrypted),
        rowCount: decryptedRows.length,
        queryDurationMs: durationMs,
        auditId,
      },
    };
  }
}
