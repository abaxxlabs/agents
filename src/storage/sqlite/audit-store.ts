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
 * SqliteAuditStore — SQLite implementation of AuditStore.
 *
 * SQLite adaptations: columns_accessed is TEXT (JSON), append-only via
 * BEFORE UPDATE/DELETE triggers, synchronous calls wrapped in async interface.
 *
 * Security: the SQLite triggers (trg_audit_no_update, trg_audit_no_delete) provide the same
 * append-only guarantee as the Postgres triggers. Any direct UPDATE or DELETE on agent_audit
 * will raise an error and abort the transaction. This is defense-in-depth alongside the
 * interface design (AuditStore has no update/delete methods) and hash chaining (tampering
 * is detectable offline).
 */

import type { Database } from 'better-sqlite3';
import type { AuditRecord } from '../../types.js';
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

  constructor(db: Database) {
    this.db = db;
  }

  /** Append an audit record. org_id is nullable — free-tier agents have no org context. */
  async append(record: AuditRecord): Promise<void> {
    this.insertRecord(record);
  }

  /**
   * Read the chain head and append the next signed record atomically under
   * BEGIN IMMEDIATE (RESERVED lock), preventing concurrent forks of the hash chain.
   */
  async appendWithChainLock(
    buildRecord: (lastRecord: AuditRecord | null) => AuditRecord,
  ): Promise<AuditRecord> {
    return this.db
      .transaction(() => {
        const row = this.loadLastRecordRow();
        const record = buildRecord(row ? this._rowToRecord(row) : null);
        this.insertRecord(record);
        return record;
      })
      .immediate();
  }

  private insertRecord(record: AuditRecord): void {
    const stmt = this.db.prepare(
      `INSERT INTO agent_audit
       (id, timestamp, agent_did, owner_did, credential_id, query_hash,
        columns_accessed, row_count, duration_ms, previous_hash, signature, org_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    );
  }

  private loadLastRecordRow(): AuditRow | undefined {
    return this.db
      .prepare(
        `SELECT id, timestamp, agent_did, owner_did, credential_id, query_hash,
              columns_accessed, row_count, duration_ms, previous_hash, signature,
              org_id
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
   * Load the chain head under BEGIN IMMEDIATE (RESERVED lock) to prevent
   * concurrent process init from forking the hash chain.
   *
   * BEGIN IMMEDIATE acquires a RESERVED lock on the database at transaction start — before any
   * read or write statement. This prevents any other writer from starting a transaction until
   * this one commits. Two processes can still read concurrently, but no other writer can begin.
   *
   * Why not BEGIN DEFERRED: DEFERRED defers lock acquisition until the first write. With DEFERRED,
   * two processes can both reach the chain-head SELECT before either writes, leaving the
   * read-then-write race open. IMMEDIATE closes it.
   *
   * App-level mutexes do not work across processes — the RESERVED lock is DB-level.
   */
  async loadLastRecordLocked(): Promise<AuditRecord | null> {
    // BEGIN IMMEDIATE: acquires RESERVED lock at transaction start — prevents concurrent writers.
    // SQLite-native equivalent of Postgres advisory lock serialization.
    const row = this.db
      .transaction(() => {
        return this.loadLastRecordRow();
      })
      .immediate();

    if (!row) return null;
    return this._rowToRecord(row);
  }

  /** Map a SQLite row to an AuditRecord. Shared by loadLastRecord and loadLastRecordLocked. */
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
    // agentDids takes precedence over agentDid when both are set.
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

  /** Count audit records with optional filters. Same WHERE logic as query(). */
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
