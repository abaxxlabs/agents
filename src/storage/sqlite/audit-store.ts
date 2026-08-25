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
 * SQLite append-only audit persistence using JSON text for accessed columns.
 * Database triggers complement the interface and hash-chain protections.
 */

import type { Database } from 'better-sqlite3';
import type { AuditRecord } from '#types/audit.js';
import type { AuditStore, AuditQueryFilter } from '../types.js';

interface AuditRow {
  id: string;
  timestamp: string;
  agent_did: string;
  owner_did: string;
  credential_id: string;
  query_hash: string;
  columns_accessed: string | string[];
  row_count: number;
  duration_ms: number;
  previous_hash: string;
  signature: string;
  org_id?: string | null;
  version?: 1 | 2 | 3;
  status?: AuditRecord['status'];
  reason?: AuditRecord['reason'];
  reason_code?: AuditRecord['reasonCode'];
}

export class SqliteAuditStore implements AuditStore {
  private readonly db: Database;
  private lockQueue: Promise<void> = Promise.resolve();

  constructor(db: Database) {
    this.db = db;
  }

  async append(record: AuditRecord): Promise<void> {
    this.insertRecord(record);
  }

  /**
   * Read the chain head and append the next signed record atomically under
   * BEGIN IMMEDIATE (RESERVED lock), preventing concurrent forks of the hash chain.
   */
  async appendWithChainLock(
    buildRecord: (lastRecord: AuditRecord | null) => AuditRecord | Promise<AuditRecord>,
  ): Promise<AuditRecord> {
    let release!: () => void;
    const acquired = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prev = this.lockQueue;
    this.lockQueue = acquired;
    await prev;

    let inTransaction = false;
    try {
      this.db.exec('BEGIN IMMEDIATE');
      inTransaction = true;
      const row = this.loadLastRecordRow();
      const record = await buildRecord(row ? this._rowToRecord(row) : null);
      this.insertRecord(record);
      this.db.exec('COMMIT');
      return record;
    } catch (err) {
      if (inTransaction) this.db.exec('ROLLBACK');
      throw err;
    } finally {
      release();
    }
  }

  private insertRecord(record: AuditRecord): void {
    const stmt = this.db.prepare(
      `INSERT INTO agent_audit
       (id, timestamp, agent_did, owner_did, credential_id, query_hash,
        columns_accessed, row_count, duration_ms, previous_hash, signature, org_id,
        version, status, reason, reason_code)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    stmt.run(
      record.id,
      record.timestamp,
      record.agentDid,
      record.ownerDid,
      record.credentialId,
      record.queryHash,
      JSON.stringify(record.columnsAccessed),
      record.rowCount,
      record.durationMs,
      record.previousHash,
      record.signature,
      record.orgId ?? null,
      record.version ?? 1,
      record.status ?? 'success',
      record.reason ?? null,
      record.reasonCode ?? null,
    );
  }

  private loadLastRecordRow(): AuditRow | undefined {
    return this.db
      .prepare(
        `SELECT id, timestamp, agent_did, owner_did, credential_id, query_hash,
              columns_accessed, row_count, duration_ms, previous_hash, signature,
              org_id, version, status, reason, reason_code
       FROM agent_audit ORDER BY timestamp DESC LIMIT 1`,
      )
      .get() as AuditRow | undefined;
  }

  async loadLastRecord(): Promise<AuditRecord | null> {
    const row = this.loadLastRecordRow();

    if (!row) return null;
    return this._rowToRecord(row);
  }

  /**
   * Uses BEGIN IMMEDIATE so the database lock precedes the chain-head read;
   * BEGIN DEFERRED would leave a cross-process read-then-write race.
   */
  async loadLastRecordLocked(): Promise<AuditRecord | null> {
    const row = this.db
      .transaction(() => {
        return this.loadLastRecordRow();
      })
      .immediate();

    if (!row) return null;
    return this._rowToRecord(row);
  }

  private _rowToRecord(row: AuditRow): AuditRecord {
    return {
      id: row.id,
      timestamp: row.timestamp,
      agentDid: row.agent_did,
      ownerDid: row.owner_did,
      credentialId: row.credential_id,
      queryHash: row.query_hash,
      columnsAccessed:
        typeof row.columns_accessed === 'string'
          ? JSON.parse(row.columns_accessed)
          : row.columns_accessed,
      rowCount: row.row_count,
      durationMs: row.duration_ms,
      previousHash: row.previous_hash,
      signature: row.signature,
      version: row.version ?? 1,
      status: row.status,
      reason: row.reason,
      reasonCode: row.reason_code,
      orgId: row.org_id ?? undefined,
    };
  }

  async query(filter?: AuditQueryFilter): Promise<AuditRecord[]> {
    let query = 'SELECT * FROM agent_audit WHERE 1=1';
    const params: unknown[] = [];

    if (filter?.id) {
      query += ' AND id = ?';
      params.push(filter.id);
    }
    if (filter?.agentDids && filter.agentDids.length > 0) {
      const placeholders = filter.agentDids.map(() => '?').join(', ');
      query += ` AND agent_did IN (${placeholders})`;
      params.push(...filter.agentDids);
    } else if (filter?.agentDid) {
      query += ' AND agent_did = ?';
      params.push(filter.agentDid);
    }
    if (filter?.since) {
      query += ' AND timestamp >= ?';
      params.push(filter.since.toISOString());
    }
    if (filter?.ownerDid) {
      query += ' AND owner_did = ?';
      params.push(filter.ownerDid);
    }
    if (filter?.credentialId) {
      query += ' AND credential_id = ?';
      params.push(filter.credentialId);
    }
    if (filter?.orgId) {
      query += ' AND org_id = ?';
      params.push(filter.orgId);
    }

    query += ' ORDER BY timestamp ASC';
    if (filter?.limit !== undefined) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }

    const rows = this.db.prepare(query).all(...params) as AuditRow[];
    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      agentDid: row.agent_did,
      ownerDid: row.owner_did,
      credentialId: row.credential_id,
      queryHash: row.query_hash,
      columnsAccessed:
        typeof row.columns_accessed === 'string'
          ? JSON.parse(row.columns_accessed)
          : row.columns_accessed,
      rowCount: row.row_count,
      durationMs: row.duration_ms,
      previousHash: row.previous_hash,
      signature: row.signature,
      version: row.version ?? (1 as 1 | 2 | 3),
      status: row.status,
      reason: row.reason,
      reasonCode: row.reason_code,
      orgId: row.org_id ?? undefined,
    }));
  }

  async count(filter?: AuditQueryFilter): Promise<number> {
    let query = 'SELECT COUNT(*) AS cnt FROM agent_audit WHERE 1=1';
    const params: unknown[] = [];

    if (filter?.id) {
      query += ' AND id = ?';
      params.push(filter.id);
    }

    if (filter?.agentDids && filter.agentDids.length > 0) {
      const placeholders = filter.agentDids.map(() => '?').join(', ');
      query += ` AND agent_did IN (${placeholders})`;
      params.push(...filter.agentDids);
    } else if (filter?.agentDid) {
      query += ' AND agent_did = ?';
      params.push(filter.agentDid);
    }
    if (filter?.since) {
      query += ' AND timestamp >= ?';
      params.push(filter.since.toISOString());
    }
    if (filter?.ownerDid) {
      query += ' AND owner_did = ?';
      params.push(filter.ownerDid);
    }
    if (filter?.credentialId) {
      query += ' AND credential_id = ?';
      params.push(filter.credentialId);
    }
    if (filter?.orgId) {
      query += ' AND org_id = ?';
      params.push(filter.orgId);
    }

    const row = this.db.prepare(query).get(...params) as { cnt: number };
    return row.cnt;
  }
}
