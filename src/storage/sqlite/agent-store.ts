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
 * SQLite implementation of AgentStore.
 *
 * Timestamps are ISO 8601 TEXT. better-sqlite3 is synchronous; async interface
 * matches the AgentStore contract (promises resolve immediately).
 */

import type { Database } from 'better-sqlite3';
import type { AgentStore, AgentRecord, AgentListFilter } from '../types.js';

interface AgentRow {
  did: string;
  name: string;
  owner_did: string;
  encrypted_private_key: Buffer | null;
  public_key: Buffer | null;
  created_at: string;
}

interface CountRow {
  cnt: number;
}

export class SqliteAgentStore implements AgentStore {
  private readonly db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  async create(agent: Omit<AgentRecord, 'createdAt'>): Promise<AgentRecord> {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(
      `INSERT INTO agents (did, name, owner_did, encrypted_private_key, public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    stmt.run(
      agent.did,
      agent.name,
      agent.ownerDid,
      agent.encryptedPrivateKey ?? null,
      agent.publicKey ?? null,
      now,
    );
    return {
      did: agent.did,
      name: agent.name,
      ownerDid: agent.ownerDid,
      encryptedPrivateKey: agent.encryptedPrivateKey ?? null,
      publicKey: agent.publicKey ?? null,
      createdAt: now,
    };
  }

  async findByDid(did: string): Promise<AgentRecord | null> {
    const row = this.db
      .prepare(
        'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents WHERE did = ?',
      )
      .get(did) as AgentRow | undefined;

    if (!row) return null;
    return {
      did: row.did,
      name: row.name,
      ownerDid: row.owner_did,
      encryptedPrivateKey: row.encrypted_private_key
        ? Buffer.from(row.encrypted_private_key)
        : null,
      publicKey: row.public_key ? Buffer.from(row.public_key) : null,
      createdAt: row.created_at,
    };
  }

  async list(filter?: AgentListFilter): Promise<AgentRecord[]> {
    const limit = Math.min(filter?.limit ?? 100, 100);

    let query =
      'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents';
    const params: unknown[] = [];

    if (filter?.ownerDid) {
      query += ' WHERE owner_did = ?';
      params.push(filter.ownerDid);
    }

    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const rows = this.db.prepare(query).all(...params) as AgentRow[];
    return rows.map((row) => ({
      did: row.did,
      name: row.name,
      ownerDid: row.owner_did,
      encryptedPrivateKey: row.encrypted_private_key
        ? Buffer.from(row.encrypted_private_key)
        : null,
      publicKey: row.public_key ? Buffer.from(row.public_key) : null,
      createdAt: row.created_at,
    }));
  }

  /**
   * Load all registered agents, unbounded (no LIMIT).
   *
   * Used by restoreAgents() at boot to reload agents into memory. Same column
   * mapping as list() but without pagination caps.
   */
  async listAll(): Promise<AgentRecord[]> {
    const rows = this.db
      .prepare(
        'SELECT did, name, owner_did, encrypted_private_key, public_key, created_at FROM agents ORDER BY created_at DESC',
      )
      .all() as AgentRow[];
    return rows.map((row) => ({
      did: row.did,
      name: row.name,
      ownerDid: row.owner_did,
      encryptedPrivateKey: row.encrypted_private_key
        ? Buffer.from(row.encrypted_private_key)
        : null,
      publicKey: row.public_key ? Buffer.from(row.public_key) : null,
      createdAt: row.created_at,
    }));
  }

  /**
   * Count registered agents, optionally filtered by ownerDid.
   *
   * SQLite COUNT() returns a number directly — no ::int cast needed (unlike
   * Postgres where COUNT returns bigint/string).
   */
  async count(filter?: { ownerDid?: string }): Promise<number> {
    if (filter?.ownerDid) {
      const row = this.db
        .prepare('SELECT COUNT(*) AS cnt FROM agents WHERE owner_did = ?')
        .get(filter.ownerDid) as CountRow;
      return row.cnt;
    }
    const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM agents').get() as CountRow;
    return row.cnt;
  }
}
