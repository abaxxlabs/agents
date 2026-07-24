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
 * PostgreSQL context storage enforcing ownership in query predicates.
 */

import type { Pool } from 'pg';
import type { ContextStore, ContextEntry, ContextListOptions, IdentityContext } from '../types.js';

export class PostgresContextStore implements ContextStore {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  async put(
    entry: Omit<ContextEntry, 'createdAt' | 'updatedAt'>,
    identity: IdentityContext,
  ): Promise<ContextEntry> {
    const isServer = identity.callerDid === identity.issuerDid;
    if (!isServer && entry.ownerDid !== identity.callerDid) {
      throw new Error(
        `Context store access denied: callerDid '${identity.callerDid}' does not match ` +
          `entry ownerDid '${entry.ownerDid}'. Only the owner or server may write entries.`,
      );
    }

    const result = await this.pool.query(
      `INSERT INTO agent_context (namespace, key, value, owner_did, created_at, updated_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (namespace, key) DO UPDATE
         SET value = EXCLUDED.value,
             updated_at = NOW()
         WHERE agent_context.owner_did = $4 OR $5 = true
       RETURNING owner_did, created_at, updated_at`,
      [entry.namespace, entry.key, JSON.stringify(entry.value), entry.ownerDid, isServer],
    );

    if (result.rows.length === 0) {
      throw new Error(
        `Context store access denied: entry '${entry.namespace}/${entry.key}' is owned by ` +
          `a different agent. Only the original owner may update it.`,
      );
    }

    return {
      namespace: entry.namespace,
      key: entry.key,
      value: entry.value,
      ownerDid: result.rows[0].owner_did,
      createdAt: result.rows[0].created_at?.toISOString?.() ?? result.rows[0].created_at,
      updatedAt: result.rows[0].updated_at?.toISOString?.() ?? result.rows[0].updated_at,
    };
  }

  async get(
    namespace: string,
    key: string,
    identity: IdentityContext,
  ): Promise<ContextEntry | null> {
    const isServer = identity.callerDid === identity.issuerDid;

    let query: string;
    let params: unknown[];

    if (isServer) {
      query = `SELECT namespace, key, value, owner_did, created_at, updated_at
               FROM agent_context WHERE namespace = $1 AND key = $2`;
      params = [namespace, key];
    } else {
      query = `SELECT namespace, key, value, owner_did, created_at, updated_at
               FROM agent_context WHERE namespace = $1 AND key = $2 AND owner_did = $3`;
      params = [namespace, key, identity.callerDid];
    }

    const result = await this.pool.query(query, params);
    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      namespace: row.namespace,
      key: row.key,
      value: typeof row.value === 'string' ? JSON.parse(row.value) : row.value,
      ownerDid: row.owner_did,
      createdAt: row.created_at?.toISOString?.() ?? row.created_at,
      updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    };
  }

  async list(
    namespace: string,
    identity: IdentityContext,
    options?: ContextListOptions,
  ): Promise<ContextEntry[]> {
    const isServer = identity.callerDid === identity.issuerDid;
    const limit = Math.min(options?.limit ?? 100, 1000);
    const offset = options?.offset ?? 0;

    let query: string;
    let params: unknown[];

    if (isServer) {
      query = `SELECT namespace, key, value, owner_did, created_at, updated_at
               FROM agent_context WHERE namespace = $1
               ORDER BY created_at ASC LIMIT $2 OFFSET $3`;
      params = [namespace, limit, offset];
    } else {
      query = `SELECT namespace, key, value, owner_did, created_at, updated_at
               FROM agent_context WHERE namespace = $1 AND owner_did = $2
               ORDER BY created_at ASC LIMIT $3 OFFSET $4`;
      params = [namespace, identity.callerDid, limit, offset];
    }

    const result = await this.pool.query(query, params);
    return result.rows.map((row) => ({
      namespace: row.namespace,
      key: row.key,
      value: typeof row.value === 'string' ? JSON.parse(row.value) : row.value,
      ownerDid: row.owner_did,
      createdAt: row.created_at?.toISOString?.() ?? row.created_at,
      updatedAt: row.updated_at?.toISOString?.() ?? row.updated_at,
    }));
  }

  async delete(namespace: string, key: string, identity: IdentityContext): Promise<boolean> {
    const isServer = identity.callerDid === identity.issuerDid;

    let query: string;
    let params: unknown[];

    if (isServer) {
      query = 'DELETE FROM agent_context WHERE namespace = $1 AND key = $2';
      params = [namespace, key];
    } else {
      query = 'DELETE FROM agent_context WHERE namespace = $1 AND key = $2 AND owner_did = $3';
      params = [namespace, key, identity.callerDid];
    }

    const result = await this.pool.query(query, params);
    return (result.rowCount ?? 0) > 0;
  }
}
