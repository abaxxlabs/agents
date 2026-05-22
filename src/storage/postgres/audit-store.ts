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
 * PostgresAuditStore — Postgres implementation of AuditStore.
 *
 * Append-only at three levels:
 *   1. Interface design — AuditStore has no update() or delete() methods.
 *   2. Database triggers — BEFORE UPDATE/DELETE triggers raise exceptions
 *      (migrations/001_init.sql: agent_audit_immutable, agent_audit_no_truncate).
 *   3. Hash chaining — each record includes SHA-256 of the previous record,
 *      making retroactive tampering detectable offline by any verifier.
 *
 * Pure persistence layer — IDs, hashes, and signatures are owned by AuditLogger.
 */

import type { Pool, PoolClient } from 'pg';
import type { AuditRecord } from '../../types/audit.js';
import type { AuditStore, AuditQueryFilter } from '../types.js';

export class PostgresAuditStore implements AuditStore {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /** Append a pre-populated audit record. org_id is nullable (free-tier agents). */
  async append(record: AuditRecord): Promise<void> {
    await this.insertRecord(this.pool, record);
  }

  /**
   * Read the chain head and append under a single advisory lock transaction.
   * Prevents cross-process hash chain forks at the DB level.
   */
  async appendWithChainLock(
    buildRecord: (lastRecord: AuditRecord | null) => AuditRecord | Promise<AuditRecord>,
  ): Promise<AuditRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1234567890)');
      const lastRecord = await this.loadLastRecordFrom(client);
      const record = await buildRecord(lastRecord);
      await this.insertRecord(client, record);
      await client.query('COMMIT');
      return record;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  private async insertRecord(executor: Pool | PoolClient, record: AuditRecord): Promise<void> {
    await executor.query(
      `INSERT INTO agent_audit
       (id, timestamp, agent_did, owner_did, credential_id, query_hash,
        columns_accessed, row_count, duration_ms, previous_hash, signature,
        org_id, version, status, reason, reason_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
      [
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
      ],
    );
  }

  /** Load the most recent audit record for hash chain initialization. Returns null in GENESIS state. */
  async loadLastRecord(): Promise<AuditRecord | null> {
    return this.loadLastRecordFrom(this.pool);
  }

  private async loadLastRecordFrom(executor: Pool | PoolClient): Promise<AuditRecord | null> {
    const result = await executor.query(
      `SELECT id, timestamp, agent_did, owner_did, credential_id, query_hash,
              columns_accessed, row_count, duration_ms, previous_hash, signature,
              org_id, version, status, reason, reason_code
       FROM agent_audit ORDER BY timestamp DESC LIMIT 1`,
    );

    if (result.rows.length === 0) return null;
    return this._rowToRecord(result.rows[0]);
  }

  /**
   * Load the last record under a Postgres advisory lock (key 1234567890).
   * Advisory rather than row-level FOR UPDATE because the table may be empty.
   * Called by AuditLogger.initialize() to prevent concurrent init forking the chain.
   */
  async loadLastRecordLocked(): Promise<AuditRecord | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1234567890)');
      const lastRecord = await this.loadLastRecordFrom(client);
      await client.query('COMMIT');

      return lastRecord;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /** Map a Postgres row to an AuditRecord. Shared by loadLastRecord and loadLastRecordLocked. */
  private _rowToRecord(row: Record<string, unknown>): AuditRecord {
    return {
      id: row.id as string,
      timestamp: row.timestamp as string,
      agentDid: row.agent_did as string,
      ownerDid: row.owner_did as string,
      credentialId: row.credential_id as string,
      queryHash: row.query_hash as string,
      columnsAccessed: row.columns_accessed as string[],
      rowCount: row.row_count as number,
      durationMs: row.duration_ms as number,
      previousHash: row.previous_hash as string,
      signature: row.signature as string,
      version: ((row.version as number) ?? 1) as 1 | 2 | 3,
      status: row.status as 'success' | 'rejected',
      reason: row.reason as string | undefined,
      reasonCode: row.reason_code as string | undefined,
      orgId: (row.org_id as string | undefined) ?? undefined,
    };
  }

  /** Query audit records with optional filters, ordered by timestamp ASC. */
  async query(filter?: AuditQueryFilter): Promise<AuditRecord[]> {
    let query = 'SELECT * FROM agent_audit WHERE 1=1';
    const params: unknown[] = [];

    if (filter?.id) {
      params.push(filter.id);
      query += ` AND id = $${params.length}`;
    }
    // agentDids (alias-aware) takes precedence over single agentDid.
    if (filter?.agentDids && filter.agentDids.length > 0) {
      params.push(filter.agentDids);
      query += ` AND agent_did = ANY($${params.length}::text[])`;
    } else if (filter?.agentDid) {
      params.push(filter.agentDid);
      query += ` AND agent_did = $${params.length}`;
    }
    if (filter?.since) {
      params.push(filter.since.toISOString());
      query += ` AND timestamp >= $${params.length}`;
    }
    if (filter?.ownerDid) {
      params.push(filter.ownerDid);
      query += ` AND owner_did = $${params.length}`;
    }
    if (filter?.credentialId) {
      params.push(filter.credentialId);
      query += ` AND credential_id = $${params.length}`;
    }
    if (filter?.orgId) {
      params.push(filter.orgId);
      query += ` AND org_id = $${params.length}`;
    }

    query += ' ORDER BY timestamp ASC';
    if (filter?.limit !== undefined) {
      params.push(filter.limit);
      query += ` LIMIT $${params.length}`;
    }

    const result = await this.pool.query(query, params);
    return result.rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      agentDid: row.agent_did,
      ownerDid: row.owner_did,
      credentialId: row.credential_id,
      queryHash: row.query_hash,
      columnsAccessed: row.columns_accessed,
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

  /** Count audit records with optional filters. `::int` cast: pg maps bigint to string. */
  async count(filter?: AuditQueryFilter): Promise<number> {
    let query = 'SELECT COUNT(*)::int AS cnt FROM agent_audit WHERE 1=1';
    const params: unknown[] = [];

    if (filter?.id) {
      params.push(filter.id);
      query += ` AND id = $${params.length}`;
    }
    if (filter?.agentDids && filter.agentDids.length > 0) {
      params.push(filter.agentDids);
      query += ` AND agent_did = ANY($${params.length}::text[])`;
    } else if (filter?.agentDid) {
      params.push(filter.agentDid);
      query += ` AND agent_did = $${params.length}`;
    }
    if (filter?.since) {
      params.push(filter.since.toISOString());
      query += ` AND timestamp >= $${params.length}`;
    }
    if (filter?.ownerDid) {
      params.push(filter.ownerDid);
      query += ` AND owner_did = $${params.length}`;
    }
    if (filter?.credentialId) {
      params.push(filter.credentialId);
      query += ` AND credential_id = $${params.length}`;
    }
    if (filter?.orgId) {
      params.push(filter.orgId);
      query += ` AND org_id = $${params.length}`;
    }

    const result = await this.pool.query(query, params);
    return result.rows[0].cnt;
  }
}
