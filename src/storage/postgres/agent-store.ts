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
 * Postgres implementation of AgentStore.
 *
 * Server-internal — no IdentityContext required; trust boundary is at the MCP layer.
 * Schema: agents (did TEXT PK, name TEXT, owner_did TEXT, created_at TIMESTAMPTZ)
 */

import type { Pool } from 'pg';
import type { AgentStore, AgentRecord, AgentListFilter } from '../types.js';

export class PostgresAgentStore implements AgentStore {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /**
   * Register a new agent. Throws on duplicate DID (Postgres PRIMARY KEY violation).
   *
   * SQL: INSERT INTO agents (did, name, owner_did) VALUES ($1, $2, $3)
   *      RETURNING created_at
   *
   * The RETURNING clause avoids a second round-trip to fetch the server-generated
   * created_at timestamp. Postgres default: NOW() in TIMESTAMPTZ.
   */
  async create(agent: Omit<AgentRecord, 'createdAt'>): Promise<AgentRecord> {
    const result = await this.pool.query(
      `INSERT INTO agents (did, name, owner_did, encrypted_private_key, public_key)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING created_at`,
      [agent.did, agent.name, agent.ownerDid, agent.encryptedPrivateKey, agent.publicKey],
    );

    return {
      did: agent.did,
      name: agent.name,
      ownerDid: agent.ownerDid,
      encryptedPrivateKey: agent.encryptedPrivateKey,
      publicKey: agent.publicKey,
      createdAt: result.rows[0].created_at?.toISOString?.() ?? result.rows[0].created_at,
    };
  }

  /**
   * Find an agent by DID. Returns null if not found.
   */
  async findByDid(did: string): Promise<AgentRecord | null> {
    const result = await this.pool.query(
      'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents WHERE did = $1',
      [did],
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      did: row.did,
      name: row.name,
      ownerDid: row.owner_did,
      encryptedPrivateKey: row.encrypted_private_key ?? null,
      publicKey: row.public_key ?? null,
      createdAt: row.created_at?.toISOString?.() ?? row.created_at,
    };
  }

  /**
   * List agents with optional filters.
   * Limit capped at 100 to prevent unbounded result sets.
   */
  async list(filter?: AgentListFilter): Promise<AgentRecord[]> {
    const limit = Math.min(filter?.limit ?? 100, 100);
    let query =
      'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents';
    const params: unknown[] = [];

    if (filter?.ownerDid) {
      params.push(filter.ownerDid);
      query += ` WHERE owner_did = $${params.length}`;
    }

    params.push(limit);
    query += ` ORDER BY created_at DESC LIMIT $${params.length}`;

    const result = await this.pool.query(query, params);
    return result.rows.map((row: Record<string, unknown>) => ({
      did: row.did as string,
      name: row.name as string,
      ownerDid: row.owner_did as string,
      encryptedPrivateKey: (row.encrypted_private_key as Buffer | null | undefined) ?? null,
      publicKey: (row.public_key as Buffer | null | undefined) ?? null,
      createdAt:
        (row.created_at as Date | undefined)?.toISOString?.() ?? (row.created_at as string),
    }));
  }

  /**
   * Load all registered agents, unbounded (no LIMIT).
   *
   * Used by restoreAgents() at boot to reload agents into memory. Same column
   * mapping as list() but without pagination caps.
   *
   * SQL: SELECT ... FROM agents ORDER BY created_at DESC
   */
  async listAll(): Promise<AgentRecord[]> {
    const result = await this.pool.query(
      'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents ORDER BY created_at DESC',
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      did: row.did as string,
      name: row.name as string,
      ownerDid: row.owner_did as string,
      encryptedPrivateKey: (row.encrypted_private_key as Buffer | null | undefined) ?? null,
      publicKey: (row.public_key as Buffer | null | undefined) ?? null,
      createdAt:
        (row.created_at as Date | undefined)?.toISOString?.() ?? (row.created_at as string),
    }));
  }

  /**
   * Count registered agents, optionally filtered by ownerDid.
   * `::int` cast: Postgres COUNT returns bigint, which pg maps to string.
   */
  async count(filter?: { ownerDid?: string }): Promise<number> {
    if (filter?.ownerDid) {
      const result = await this.pool.query(
        'SELECT COUNT(*)::int AS cnt FROM agents WHERE owner_did = $1',
        [filter.ownerDid],
      );
      return result.rows[0].cnt;
    }
    const result = await this.pool.query('SELECT COUNT(*)::int AS cnt FROM agents');
    return result.rows[0].cnt;
  }
}
