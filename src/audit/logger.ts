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

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { AgentSigner } from '#types/index.js';
import type { AuditRecord, AuditEntry, MessageAuditEvent } from '#types/index.js';
import { AuditWriteFailedError } from '#errors/index.js';
import { decodeJwt, verifyJwtSignature } from '#crypto/jwt.js';
import type { AuditQueryFilter, AuditStore } from '#storage/index.js';
import type { DidAliasRegistry } from '#did/alias.js';

export type { AuditRecord, AuditEntry } from '#types/index.js';

const MESSAGE_FIELDS = [
  'eventKind',
  'direction',
  'counterpartAgentDid',
  'counterpartInstanceDid',
  'messageRecordId',
  'messageDigest',
] as const;

export type AuditOperation = 'query' | 'rejection' | 'message';

function signedAuditData(record: Omit<AuditRecord, 'signature'>): Record<string, unknown> {
  const data: Record<string, unknown> = {
    id: record.id,
    timestamp: record.timestamp,
    agentDid: record.agentDid,
    ownerDid: record.ownerDid,
    credentialId: record.credentialId,
    queryHash: record.queryHash,
    columnsAccessed: record.columnsAccessed,
    rowCount: record.rowCount,
    durationMs: record.durationMs,
  };

  if (record.orgId !== undefined) {
    data.orgId = record.orgId;
  }
  if (record.delegatorDid !== undefined) {
    data.delegatorDid = record.delegatorDid;
  }
  if (record.delegatedGrantId !== undefined) {
    data.delegatedGrantId = record.delegatedGrantId;
  }
  for (const key of MESSAGE_FIELDS) {
    if (record[key] !== undefined) data[key] = record[key];
  }
  // A sent or received message and a refused one differ only in their outcome, so the agent
  // signs it. Earlier versions keep the payload they always had.
  if (record.version === 5) {
    data.version = record.version;
    data.status = record.status;
    if (record.reason !== undefined) data.reason = record.reason;
    if (record.reasonCode !== undefined) data.reasonCode = record.reasonCode;
  }

  return data;
}

function signedDataMatches(actual: unknown, expected: Record<string, unknown>): boolean {
  if (typeof actual !== 'object' || actual === null || Array.isArray(actual)) return false;
  const actualRecord = actual as Record<string, unknown>;
  const expectedKeys = Object.keys(expected);
  if (Object.keys(actualRecord).length !== expectedKeys.length) return false;
  for (const key of expectedKeys) {
    const expectedValue = expected[key];
    const actualValue = actualRecord[key];
    if (Array.isArray(expectedValue)) {
      if (!Array.isArray(actualValue)) return false;
      if (actualValue.length !== expectedValue.length) return false;
      if (actualValue.some((value, index) => value !== expectedValue[index])) return false;
      continue;
    }
    if (actualValue !== expectedValue) return false;
  }
  return true;
}

async function signAuditRecord(
  record: Omit<AuditRecord, 'signature'>,
  signer: AgentSigner,
): Promise<string> {
  const payload = {
    aud: 'agents-audit',
    iat: Math.floor(Date.now() / 1000),
    data: signedAuditData(record),
  };

  return await signer.signJwt(payload);
}

export function hashCredential(jwt: string): string {
  return createHash('sha256').update(jwt).digest('hex').slice(0, 16);
}

/** Privacy — don't store raw SQL. */
export function hashQuery(sql: string): string {
  return createHash('sha256').update(sql).digest('hex');
}

/** Version tag determines which fields enter the hash — must match the schema at creation time. */
export function hashAuditRecord(record: Omit<AuditRecord, 'signature'>): string {
  const base: Record<string, unknown> = {
    id: record.id,
    timestamp: record.timestamp,
    agentDid: record.agentDid,
    ownerDid: record.ownerDid,
    credentialId: record.credentialId,
    queryHash: record.queryHash,
    columnsAccessed: record.columnsAccessed,
    rowCount: record.rowCount,
    durationMs: record.durationMs,
    previousHash: record.previousHash,
  };

  if (record.version === 5) {
    base.version = record.version;
    base.status = record.status;
    base.reason = record.reason;
    base.reasonCode = record.reasonCode;
    base.orgId = record.orgId;
    base.delegatorDid = record.delegatorDid;
    base.delegatedGrantId = record.delegatedGrantId;
    base.eventKind = record.eventKind;
    base.direction = record.direction;
    base.counterpartAgentDid = record.counterpartAgentDid;
    base.counterpartInstanceDid = record.counterpartInstanceDid;
    base.messageRecordId = record.messageRecordId;
    base.messageDigest = record.messageDigest;
  } else if (record.version === 4) {
    base.version = record.version;
    base.status = record.status;
    base.reason = record.reason;
    base.reasonCode = record.reasonCode;
    base.orgId = record.orgId;
    base.delegatorDid = record.delegatorDid;
    base.delegatedGrantId = record.delegatedGrantId;
  } else if (record.version === 3) {
    base.version = record.version;
    base.status = record.status;
    base.reason = record.reason;
    base.reasonCode = record.reasonCode;
    base.orgId = record.orgId;
  } else if (record.version === 2) {
    base.version = record.version;
    base.status = record.status;
    base.reason = record.reason;
    base.reasonCode = record.reasonCode;
  }

  return createHash('sha256').update(JSON.stringify(base)).digest('hex');
}

/** Constant-time — verifyAuditChain() may be called over HTTP. */
function hashesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export interface AuditLoggerOptions {
  auditStore: AuditStore;
  /** Expands agentDid to all equivalent DIDs in export(), preserving continuity across migrations. */
  aliasRegistry?: DidAliasRegistry;
  enabled?: boolean;
}

export interface AuditLoggerTelemetrySink {
  auditWriteFailed(event: { operation: AuditOperation; error: unknown }): void;
}

export class AuditLogger {
  private auditStore: AuditStore;
  private aliasRegistry?: DidAliasRegistry;
  private enabled: boolean;
  private telemetry?: AuditLoggerTelemetrySink;
  private lastRecordHash: string = 'GENESIS';
  private lastTimestampMs = 0;
  private initialized: boolean = false;
  private chainLock: Promise<void> = Promise.resolve();

  constructor(options: AuditLoggerOptions) {
    this.auditStore = options.auditStore;
    this.aliasRegistry = options.aliasRegistry;
    this.enabled = options.enabled ?? true;
  }

  /** Setter-based so consumers without a logging stack don't need to supply it at construction. */
  setTelemetrySink(sink: AuditLoggerTelemetrySink | undefined): void {
    this.telemetry = sink;
  }

  private emitAuditWriteFailedTelemetry(event: {
    operation: AuditOperation;
    error: unknown;
  }): void {
    try {
      this.telemetry?.auditWriteFailed(event);
    } catch {
      // Best-effort — must not alter audit semantics.
    }
  }

  private setChainHead(lastRecord: AuditRecord | null): void {
    this.lastRecordHash = lastRecord ? hashAuditRecord(lastRecord) : 'GENESIS';
    if (lastRecord) this.noteTimestamp(lastRecord.timestamp);
    this.initialized = true;
  }

  private advanceChain(record: AuditRecord): void {
    this.lastRecordHash = hashAuditRecord(record);
    this.noteTimestamp(record.timestamp);
    this.initialized = true;
  }

  /** Stores return the timestamp as written or, on PostgreSQL, as a Date. */
  private noteTimestamp(timestamp: string | Date): void {
    const ms = new Date(timestamp).getTime();
    if (Number.isFinite(ms) && ms > this.lastTimestampMs) this.lastTimestampMs = ms;
  }

  /**
   * The chain head is the record with the latest timestamp, so two records must never share
   * one. Each timestamp is later than the head it chains to, by a millisecond when the clock
   * has not moved or has stepped back.
   */
  private nextTimestamp(): string {
    const now = Date.now();
    this.lastTimestampMs = now > this.lastTimestampMs ? now : this.lastTimestampMs + 1;
    return new Date(this.lastTimestampMs).toISOString();
  }

  private async buildQueryRecord(entry: AuditEntry, signer: AgentSigner): Promise<AuditRecord> {
    const record: Omit<AuditRecord, 'signature'> = {
      id: randomUUID(),
      timestamp: this.nextTimestamp(),
      agentDid: entry.agentDid,
      ownerDid: entry.ownerDid,
      credentialId: hashCredential(entry.credentialJwt),
      queryHash: hashQuery(entry.sql),
      columnsAccessed: entry.columnsAccessed,
      rowCount: entry.rowCount,
      durationMs: entry.durationMs,
      previousHash: this.lastRecordHash,
      version: 4,
      status: 'success',
      orgId: entry.orgId,
      delegatorDid: entry.delegatorDid,
      delegatedGrantId: entry.delegatedGrantId,
    };

    return { ...record, signature: await signAuditRecord(record, signer) };
  }

  private async buildRejectionRecord(
    reason: string,
    reasonCode: string,
    signer?: AgentSigner,
    context?: {
      agentDid?: string;
      ownerDid?: string;
      sql?: string;
      orgId?: string;
      delegatorDid?: string;
      delegatedGrantId?: string;
    },
  ): Promise<AuditRecord> {
    const record: Omit<AuditRecord, 'signature'> = {
      id: randomUUID(),
      timestamp: this.nextTimestamp(),
      agentDid: context?.agentDid ?? 'unknown',
      ownerDid: context?.ownerDid ?? 'unknown',
      credentialId: 'none',
      queryHash: context?.sql ? hashQuery(context.sql) : 'none',
      columnsAccessed: [],
      rowCount: 0,
      durationMs: 0,
      previousHash: this.lastRecordHash,
      version: 4,
      status: 'rejected',
      reason,
      reasonCode,
      orgId: context?.orgId,
      delegatorDid: context?.delegatorDid,
      delegatedGrantId: context?.delegatedGrantId,
    };

    return { ...record, signature: signer ? await signAuditRecord(record, signer) : 'unsigned' };
  }

  private async buildMessageRecord(
    event: MessageAuditEvent,
    signer: AgentSigner,
  ): Promise<AuditRecord> {
    const record: Omit<AuditRecord, 'signature'> = {
      id: randomUUID(),
      timestamp: this.nextTimestamp(),
      agentDid: event.agentDid,
      ownerDid: event.ownerDid,
      credentialId: 'none',
      queryHash: 'none',
      columnsAccessed: [],
      rowCount: 0,
      durationMs: 0,
      previousHash: this.lastRecordHash,
      version: 5,
      status: event.status,
      reason: event.reason,
      reasonCode: event.reasonCode,
      orgId: event.orgId,
      eventKind: 'message',
      direction: event.direction,
      counterpartAgentDid: event.counterpartAgentDid,
      counterpartInstanceDid: event.counterpartInstanceDid,
      messageRecordId: event.messageRecordId,
      messageDigest: event.messageDigest,
    };

    return { ...record, signature: await signAuditRecord(record, signer) };
  }

  private async appendBuiltRecord(
    operation: AuditOperation,
    buildRecord: () => Promise<AuditRecord>,
  ): Promise<AuditRecord> {
    if (!this.enabled) {
      if (!this.initialized) this.setChainHead(null);
      const record = await buildRecord();
      this.advanceChain(record);
      return record;
    }

    const store = this.auditStore;
    const appendWithChainLock = store.appendWithChainLock?.bind(store);
    if (appendWithChainLock) {
      let fullRecord: AuditRecord | undefined;
      let buildError: unknown;

      try {
        fullRecord = await appendWithChainLock(async (lastRecord) => {
          this.setChainHead(lastRecord);
          try {
            fullRecord = await buildRecord();
            return fullRecord;
          } catch (err) {
            buildError = err;
            throw err;
          }
        });
        this.advanceChain(fullRecord);
        return fullRecord;
      } catch (err) {
        if (err === buildError) throw err;
        return this.handleAuditAppendError(operation, err, fullRecord, buildRecord);
      }
    }

    await this.initializeUnlocked();
    const fullRecord = await buildRecord();

    try {
      await store.append(fullRecord);
      this.advanceChain(fullRecord);
      return fullRecord;
    } catch (err) {
      return this.handleAuditAppendError(operation, err, fullRecord, buildRecord);
    }
  }

  private handleAuditAppendError(
    operation: AuditOperation,
    err: unknown,
    _fullRecord?: AuditRecord,
    _buildRecord?: () => Promise<AuditRecord>,
  ): AuditRecord {
    const reason = err instanceof Error ? err.message : 'Unknown error';
    this.emitAuditWriteFailedTelemetry({ operation, error: err });
    throw new AuditWriteFailedError(reason);
  }

  /** Stores implementing appendWithChainLock() don't need this — they load lazily per-append. */
  async initialize(): Promise<void> {
    await this.withChainLock(() => this.initializeUnlocked());
  }

  private async initializeUnlocked(): Promise<void> {
    if (this.initialized) return;
    try {
      const store = this.auditStore;
      const lastRecord = await store.loadLastRecordLocked();
      this.setChainHead(lastRecord);
    } catch {
      // Table may not exist yet.
      this.setChainHead(null);
    }
  }

  private async withChainLock<T>(fn: () => Promise<T>): Promise<T> {
    let release: () => void;
    const acquired = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previousLock = this.chainLock;
    this.chainLock = acquired;
    await previousLock;
    try {
      return await fn();
    } finally {
      release!();
    }
  }

  async log(entry: AuditEntry, signer: AgentSigner): Promise<AuditRecord> {
    return this.withChainLock(async () => {
      return this.appendBuiltRecord('query', () => this.buildQueryRecord(entry, signer));
    });
  }

  /** `signer` is optional — some rejections occur before agent identity is established. */
  async logRejection(
    reason: string,
    reasonCode: string,
    signer?: AgentSigner,
    context?: {
      agentDid?: string;
      ownerDid?: string;
      sql?: string;
      orgId?: string;
      delegatorDid?: string;
      delegatedGrantId?: string;
    },
  ): Promise<AuditRecord> {
    return this.withChainLock(async () => {
      return this.appendBuiltRecord('rejection', () =>
        this.buildRejectionRecord(reason, reasonCode, signer, context),
      );
    });
  }

  /** Records one sent or received agent message as a version 5 record, signed by the acting agent. */
  async logMessageEvent(event: MessageAuditEvent, signer: AgentSigner): Promise<AuditRecord> {
    return this.withChainLock(async () => {
      return this.appendBuiltRecord('message', () => this.buildMessageRecord(event, signer));
    });
  }

  async verifyRecord(record: AuditRecord, agentPublicKey: Uint8Array): Promise<boolean> {
    try {
      if (!(await verifyJwtSignature(record.signature, agentPublicKey))) return false;
      const { payload } = decodeJwt(record.signature);
      return (
        payload.aud === 'agents-audit' && signedDataMatches(payload.data, signedAuditData(record))
      );
    } catch {
      return false;
    }
  }

  /** Does NOT verify signatures (use verifyRecord). Cannot detect deleted rows. */
  async verifyAuditChain(filter?: Pick<AuditQueryFilter, 'agentDid' | 'since' | 'orgId'>): Promise<{
    ok: boolean;
    totalRecords: number;
    /** true when a filter was applied. */
    partial: boolean;
    failedAt?: string;
    error?: string;
  }> {
    const records = await this.export(filter);
    const hasFilter = !!(filter?.agentDid || filter?.since || filter?.orgId);
    const hasNonConsecutiveFilter = !!(filter?.agentDid || filter?.orgId);

    if (records.length === 0) return { ok: true, totalRecords: 0, partial: hasFilter };

    let expectedPreviousHash = hasFilter ? records[0].previousHash : 'GENESIS';

    for (const record of records) {
      if (!hashesEqual(record.previousHash, expectedPreviousHash)) {
        const baseDetail = `expected previousHash ${expectedPreviousHash.slice(0, 16)}…, got ${record.previousHash.slice(0, 16)}…`;
        const error = hasNonConsecutiveFilter
          ? `Hash chain broken in filtered subset at record ${record.id}: ${baseDetail}. ` +
            `This may reflect non-consecutive records in the filtered view rather than tampering. ` +
            `Call verifyAuditChain() without filters for root-of-chain proof.`
          : `Hash chain broken at record ${record.id}: ${baseDetail}`;
        return {
          ok: false,
          totalRecords: records.length,
          partial: hasFilter,
          failedAt: record.id,
          error,
        };
      }
      expectedPreviousHash = hashAuditRecord(record);
    }
    return { ok: true, totalRecords: records.length, partial: hasFilter };
  }

  /** orgId is forwarded in alias-expanded queries to prevent cross-org leakage. */
  async export(filter?: AuditQueryFilter): Promise<AuditRecord[]> {
    const store = this.auditStore;

    if (filter?.agentDid && this.aliasRegistry) {
      const allDids = this.aliasRegistry.allEquivalentDids(filter.agentDid);
      if (allDids.length > 1) {
        const expandedFilter: AuditQueryFilter = { ...filter, agentDids: allDids };
        delete expandedFilter.agentDid;
        return store.query(expandedFilter);
      }
    }

    return store.query(filter);
  }
}
