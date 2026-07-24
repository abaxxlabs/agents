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

/** PostgreSQL implementation of AgentStore. */

import type { Pool } from 'pg';
import type { AgentStore, AgentRecord, AgentListFilter } from '../types.js';

export class PostgresAgentStore implements AgentStore {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

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

  /** The int cast prevents pg from returning COUNT as a string. */
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
