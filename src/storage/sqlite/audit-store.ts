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
  version?: AuditRecord['version'];
  status?: AuditRecord['status'];
  reason?: AuditRecord['reason'];
  reason_code?: AuditRecord['reasonCode'];
  delegator_did?: string | null;
  delegated_grant_id?: string | null;
  event_kind?: AuditRecord['eventKind'] | null;
  direction?: AuditRecord['direction'] | null;
  counterpart_agent_did?: string | null;
  counterpart_instance_did?: string | null;
  message_record_id?: string | null;
  message_digest?: string | null;
}

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

  if (filter?.id) {
    where += ' AND id = ?';
    params.push(filter.id);
  }
  if (filter?.agentDids && filter.agentDids.length > 0) {
    const placeholders = filter.agentDids.map(() => '?').join(', ');
    where += ` AND agent_did IN (${placeholders})`;
    params.push(...filter.agentDids);
  } else if (filter?.agentDid) {
    where += ' AND agent_did = ?';
    params.push(filter.agentDid);
  }
  if (filter?.since) {
    where += ' AND timestamp >= ?';
    params.push(filter.since.toISOString());
  }
  if (filter?.ownerDid) {
    where += ' AND owner_did = ?';
    params.push(filter.ownerDid);
  }
  if (filter?.credentialId) {
    where += ' AND credential_id = ?';
    params.push(filter.credentialId);
  }
  if (filter?.orgId) {
    where += ' AND org_id = ?';
    params.push(filter.orgId);
  }
  // Records written before version 5 carry no event_kind and are queries.
  if (filter?.eventKind) {
    where += " AND COALESCE(event_kind, 'query') = ?";
    params.push(filter.eventKind);
  }
  if (filter?.messageRecordId) {
    where += ' AND message_record_id = ?';
    params.push(filter.messageRecordId);
  }
  if (filter?.messageRecordIds) {
    // An empty list matches nothing, as it does on PostgreSQL.
    if (filter.messageRecordIds.length === 0) {
      where += ' AND 0';
    } else {
      const placeholders = filter.messageRecordIds.map(() => '?').join(', ');
      where += ` AND message_record_id IN (${placeholders})`;
      params.push(...filter.messageRecordIds);
    }
  }
  if (filter?.direction) {
    where += ' AND direction = ?';
    params.push(filter.direction);
  }

  return { where, params };
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
    const { columns, values } = insertShape(record);
    const placeholders = columns.map(() => '?').join(', ');
    this.db
      .prepare(`INSERT INTO agent_audit (${columns.join(', ')}) VALUES (${placeholders})`)
      .run(...values);
  }

  private loadLastRecordRow(): AuditRow | undefined {
    return this.db.prepare('SELECT * FROM agent_audit ORDER BY timestamp DESC LIMIT 1').get() as
      AuditRow | undefined;
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
      reason: row.reason ?? undefined,
      reasonCode: row.reason_code ?? undefined,
      orgId: row.org_id ?? undefined,
      delegatorDid: row.delegator_did ?? undefined,
      delegatedGrantId: row.delegated_grant_id ?? undefined,
      eventKind: row.event_kind ?? undefined,
      direction: row.direction ?? undefined,
      counterpartAgentDid: row.counterpart_agent_did ?? undefined,
      counterpartInstanceDid: row.counterpart_instance_did ?? undefined,
      messageRecordId: row.message_record_id ?? undefined,
      messageDigest: row.message_digest ?? undefined,
    };
  }

  async query(filter?: AuditQueryFilter): Promise<AuditRecord[]> {
    const { where, params } = buildWhere(filter);
    let query = `SELECT * FROM agent_audit${where} ORDER BY timestamp ASC`;
    if (filter?.limit !== undefined) {
      query += ' LIMIT ?';
      params.push(filter.limit);
    }

    const rows = this.db.prepare(query).all(...params) as AuditRow[];
    return rows.map((row) => this._rowToRecord(row));
  }

  async count(filter?: AuditQueryFilter): Promise<number> {
    const { where, params } = buildWhere(filter);
    const row = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM agent_audit${where}`)
      .get(...params) as {
      cnt: number;
    };
    return row.cnt;
  }
}
