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
 * PostgreSQL append-only audit persistence. AuditLogger owns IDs, hashes, and signatures.
 */

import type { Pool, PoolClient } from 'pg';
import type { AuditRecord } from '#types/audit.js';
import type { AuditStore, AuditQueryFilter } from '../types.js';

const BASE_COLUMNS = [
  'id',
  'timestamp',
  'agent_did',
  'owner_did',
  'credential_id',
  'query_hash',
  'columns_accessed',
  'row_count',
  'duration_ms',
  'previous_hash',
  'signature',
  'org_id',
  'version',
  'status',
  'reason',
  'reason_code',
  'delegator_did',
  'delegated_grant_id',
];

/** Present only once the message event migration has run. Query records never name them. */
const MESSAGE_COLUMNS = [
  'event_kind',
  'direction',
  'counterpart_agent_did',
  'counterpart_instance_did',
  'message_record_id',
  'message_digest',
];

function baseValues(record: AuditRecord): unknown[] {
  return [
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
    record.delegatorDid ?? null,
    record.delegatedGrantId ?? null,
  ];
}

function messageValues(record: AuditRecord): unknown[] {
  return [
    record.eventKind ?? null,
    record.direction ?? null,
    record.counterpartAgentDid ?? null,
    record.counterpartInstanceDid ?? null,
    record.messageRecordId ?? null,
    record.messageDigest ?? null,
  ];
}

/**
 * Columns and values for one insert. Only message records name the message columns, so query
 * records keep writing on a database where that migration has not run yet.
 */
function insertShape(record: AuditRecord): { columns: string[]; values: unknown[] } {
  if (record.version !== 5) return { columns: BASE_COLUMNS, values: baseValues(record) };
  return {
    columns: [...BASE_COLUMNS, ...MESSAGE_COLUMNS],
    values: [...baseValues(record), ...messageValues(record)],
  };
}

function buildWhere(filter?: AuditQueryFilter): { where: string; params: unknown[] } {
  let where = ' WHERE 1=1';
  const params: unknown[] = [];
  const add = (clause: (placeholder: string) => string, value: unknown) => {
    params.push(value);
    where += ` AND ${clause(`$${params.length}`)}`;
  };

  if (filter?.id) add((p) => `id = ${p}`, filter.id);
  if (filter?.agentDids && filter.agentDids.length > 0) {
    add((p) => `agent_did = ANY(${p}::text[])`, filter.agentDids);
  } else if (filter?.agentDid) {
    add((p) => `agent_did = ${p}`, filter.agentDid);
  }
  if (filter?.since) add((p) => `timestamp >= ${p}`, filter.since.toISOString());
  if (filter?.ownerDid) add((p) => `owner_did = ${p}`, filter.ownerDid);
  if (filter?.credentialId) add((p) => `credential_id = ${p}`, filter.credentialId);
  if (filter?.orgId) add((p) => `org_id = ${p}`, filter.orgId);
  // Records written before version 5 carry no event_kind and are queries.
  if (filter?.eventKind) add((p) => `COALESCE(event_kind, 'query') = ${p}`, filter.eventKind);
  if (filter?.messageRecordId) add((p) => `message_record_id = ${p}`, filter.messageRecordId);
  if (filter?.messageRecordIds) {
    add((p) => `message_record_id = ANY(${p}::text[])`, [...filter.messageRecordIds]);
  }
  if (filter?.direction) add((p) => `direction = ${p}`, filter.direction);

  return { where, params };
}

export class PostgresAuditStore implements AuditStore {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

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
    const { columns, values } = insertShape(record);
    const placeholders = columns.map((_, index) => `$${index + 1}`).join(', ');
    await executor.query(
      `INSERT INTO agent_audit (${columns.join(', ')}) VALUES (${placeholders})`,
      values,
    );
  }

  async loadLastRecord(): Promise<AuditRecord | null> {
    return this.loadLastRecordFrom(this.pool);
  }

  private async loadLastRecordFrom(executor: Pool | PoolClient): Promise<AuditRecord | null> {
    const result = await executor.query(
      'SELECT * FROM agent_audit ORDER BY timestamp DESC LIMIT 1',
    );

    if (result.rows.length === 0) return null;
    return this._rowToRecord(result.rows[0]);
  }

  /**
   * Uses an advisory lock because the table may be empty and have no row to lock.
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

  private _rowToRecord(row: Record<string, unknown>): AuditRecord {
    return {
      id: row.id as string,
      timestamp: (row.timestamp as Date | undefined)?.toISOString?.() ?? (row.timestamp as string),
      agentDid: row.agent_did as string,
      ownerDid: row.owner_did as string,
      credentialId: row.credential_id as string,
      queryHash: row.query_hash as string,
      columnsAccessed: row.columns_accessed as string[],
      rowCount: row.row_count as number,
      durationMs: row.duration_ms as number,
      previousHash: row.previous_hash as string,
      signature: row.signature as string,
      version: ((row.version as number) ?? 1) as AuditRecord['version'],
      status: row.status as 'success' | 'rejected',
      reason: (row.reason as string | null) ?? undefined,
      reasonCode: (row.reason_code as string | null) ?? undefined,
      orgId: (row.org_id as string | undefined) ?? undefined,
      delegatorDid: (row.delegator_did as string | undefined) ?? undefined,
      delegatedGrantId: (row.delegated_grant_id as string | undefined) ?? undefined,
      eventKind: (row.event_kind as AuditRecord['eventKind'] | null) ?? undefined,
      direction: (row.direction as AuditRecord['direction'] | null) ?? undefined,
      counterpartAgentDid: (row.counterpart_agent_did as string | null) ?? undefined,
      counterpartInstanceDid: (row.counterpart_instance_did as string | null) ?? undefined,
      messageRecordId: (row.message_record_id as string | null) ?? undefined,
      messageDigest: (row.message_digest as string | null) ?? undefined,
    };
  }

  async query(filter?: AuditQueryFilter): Promise<AuditRecord[]> {
    const { where, params } = buildWhere(filter);
    let query = `SELECT * FROM agent_audit${where} ORDER BY timestamp ASC`;
    if (filter?.limit !== undefined) {
      params.push(filter.limit);
      query += ` LIMIT $${params.length}`;
    }

    const result = await this.pool.query(query, params);
    return result.rows.map((row) => this._rowToRecord(row));
  }

  /** The int cast prevents pg from returning COUNT as a string. */
  async count(filter?: AuditQueryFilter): Promise<number> {
    const { where, params } = buildWhere(filter);
    const result = await this.pool.query(
      `SELECT COUNT(*)::int AS cnt FROM agent_audit${where}`,
      params,
    );
    return result.rows[0].cnt;
  }
}
