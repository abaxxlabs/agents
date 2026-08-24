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

import type { Pool } from 'pg';
import type { RegisteredAgent } from '#types/auth.js';
import type { ScopeMode } from '#types/config.js';
import type { QueryOptions, ScopedResult } from './types.js';
import { AgentScopeError, QueryRejectedError } from '#errors/index.js';
import type { AgentStore } from '#storage/types.js';
import { VcVerifier } from '#identity/index.js';
import { AuditLogger } from '#audit/index.js';
import type { DidAliasRegistry } from '#did/alias.js';
import type { Did, TableName } from '#types/domain.js';
import { authorizeQuery } from './query-policy.js';
import { QueryAuthorizer } from './authorization.js';
import { QueryRunner } from './query-execution.js';
import { ResultAssembler } from './result-assembly.js';

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

/**
 * Orchestrates the scoped query pipeline. Authorization, SQL validation,
 * execution/decryption, and result/audit assembly are delegated to focused
 * modules; this class calls them in order without implementing their policy.
 */
export class ScopeEngine {
  private authorizer: QueryAuthorizer;
  private runner: QueryRunner;
  private assembler: ResultAssembler;
  private agents: Map<string, RegisteredAgent>;
  private auditLogger: AuditLogger;

  constructor(options: ScopeEngineOptions) {
    this.authorizer = new QueryAuthorizer({
      verifier: options.verifier,
      agents: options.agents,
      verifierDid: options.verifierDid,
      didAliases: options.didAliases,
      agentStore: options.agentStore,
    });
    this.runner = new QueryRunner({
      pool: options.pool,
      columnKeys: options.columnKeys,
      encryptedColumns: options.encryptedColumns,
    });
    this.assembler = new ResultAssembler({
      auditLogger: options.auditLogger,
      agents: options.agents,
    });
    this.agents = options.agents;
    this.auditLogger = options.auditLogger;
    const mode = options.scopeMode ?? 'projection';
    if (mode !== 'projection') {
      throw new Error(`Invalid scopeMode "${mode}" — must be "projection".`);
    }
  }

  /**
   * Execute a scoped query.
   *
   * The agent presents a DID + credential JWT + SQL query.
   * The engine verifies the credential, validates the query
   * (read-only, declared table, projection boundary), executes
   * the original SQL, and decrypts only the columns the credential
   * authorizes. Out-of-scope references are rejected before execution.
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

    const authorization = await this.authorizer.authorize({
      agent: options.agent,
      credential: options.credential,
      credentials: options.credentials,
      requirePresentation: options.requirePresentation,
    });

    // Validate table name — must be a safe SQL identifier (letters, digits,
    // underscores, optional schema-qualified with a single dot). Rejects
    // injection via options.table before it reaches query authorization
    // or decryptRow.
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/.test(options.table)) {
      throw new QueryRejectedError(options.agent, `Invalid table name: "${options.table}"`);
    }

    const agentDid = options.agent as Did;
    const table = options.table as TableName;

    await authorizeQuery({
      sql: options.sql,
      tableName: table,
      agentDid,
      columnActionMap: authorization.columnActions,
    });

    const execution = await this.runner.execute({
      sql: options.sql,
      params: options.params,
      table: options.table,
      scopeColumns: authorization.scopeColumns,
    });

    const durationMs = Date.now() - startTime;

    return this.assembler.assemble({
      agent: options.agent,
      ownerDid: authorization.ownerDid,
      credentialJwt: authorization.allJwts[0],
      sql: options.sql,
      columnsAccessed: authorization.scopeColumns,
      rowCount: execution.decryptedRows.length,
      durationMs,
      orgId: options.orgId,
      decryptedRows: execution.decryptedRows,
      columnsDecrypted: execution.columnsDecrypted,
      columnsEncrypted: execution.columnsEncrypted,
    });
  }
}
