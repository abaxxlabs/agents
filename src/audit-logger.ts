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
 * Audit Logger — creates signed, hash-chained audit records for every agent query.
 * Each record is signed with the agent's Ed25519 key (verifiable offline).
 * An optional telemetry sink can observe write failures without changing audit semantics.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';
import type { AuditRecord, AuditEntry, AgentSigner } from './types.js';
import { AuditWriteFailedError } from './errors.js';
import { verifyJwtSignature } from './vc-verifier.js';
import type { AuditQueryFilter, AuditStore } from './storage/types.js';
import type { DidAliasRegistry } from './did-alias.js';

// ─── JWS Signing for Audit Records ──────────────────────────────

/**
 * Create a compact JWS signature over an audit record payload.
 * Uses the agent's opaque signer (Ed25519 / EdDSA).
 */
async function signAuditRecord(record: Omit<AuditRecord, 'signature'>, signer: AgentSigner): Promise<string> {
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

  const payload = {
    aud: 'agents-audit',
    iat: Math.floor(Date.now() / 1000),
    data,
  };

  return await signer.signJwt(payload);
}

/**
 * Hash a credential JWT to produce a credential ID.
 */
export function hashCredential(jwt: string): string {
  return createHash('sha256').update(jwt).digest('hex').slice(0, 16);
}

/**
 * Hash a SQL query for the audit record (privacy — don't store raw SQL).
 */
export function hashQuery(sql: string): string {
  return createHash('sha256').update(sql).digest('hex');
}

/**
 * Hash an audit record for chain linking.
 *
 * Records carry a version tag that determines which fields enter the hash.
 * The branching must match the schema that was active when the record was
 * created, otherwise chain verification produces a different digest.
 */
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

  if (record.version === 3) {
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

// ─── Timing-Safe Hash Comparison ─────────────────────────────────

/**
 * Compare two hex-encoded SHA-256 hashes in constant time.
 *
 * `!==` short-circuits on the first byte mismatch, leaking timing information about how much
 * of the hash matches. Timing-safe comparison prevents hash-oracle attacks when invoked from
 * an authenticated HTTP endpoint — `verifyAuditChain()` may be called over HTTP.
 *
 * Length check first because `timingSafeEqual` throws on mismatched lengths; a wrong-length
 * hash is definitionally wrong.
 */
function hashesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// ─── Audit Logger ────────────────────────────────────────────────

export interface AuditLoggerOptions {
  /** Required. Inject a concrete AuditStore (Postgres, SQLite, or test mock). */
  auditStore: AuditStore;

  /**
   * Optional alias registry. When set, export() expands a single agentDid
   * to all equivalent DIDs, preserving audit-trail continuity across identity migrations.
   */
  aliasRegistry?: DidAliasRegistry;

  enabled?: boolean; // default: true
}

export interface AuditLoggerTelemetrySink {
  auditWriteFailed(event: {
    operation: 'query' | 'rejection';
    error: unknown;
  }): void;
}

export class AuditLogger {
  private auditStore: AuditStore;
  private aliasRegistry?: DidAliasRegistry;
  private enabled: boolean;
  private telemetry?: AuditLoggerTelemetrySink;
  /** Hash of the last audit record (for chain linking). */
  private lastRecordHash: string = 'GENESIS';
  private initialized: boolean = false;
  /** Serializes chain operations so concurrent calls never read the same lastRecordHash. */
  private chainLock: Promise<void> = Promise.resolve();

  constructor(options: AuditLoggerOptions) {
    this.auditStore = options.auditStore;
    this.aliasRegistry = options.aliasRegistry;
    this.enabled = options.enabled ?? true;
  }

  /**
   * Attach a best-effort telemetry sink. Setter-based so consumers without a
   * logging stack don't need to supply it at construction.
   */
  setTelemetrySink(sink: AuditLoggerTelemetrySink | undefined): void {
    this.telemetry = sink;
  }

  private emitAuditWriteFailedTelemetry(event: {
    operation: 'query' | 'rejection';
    error: unknown;
  }): void {
    try {
      this.telemetry?.auditWriteFailed(event);
    } catch {
      // Operational telemetry is best-effort and must not alter audit semantics.
    }
  }

  private setChainHead(lastRecord: AuditRecord | null): void {
    this.lastRecordHash = lastRecord ? hashAuditRecord(lastRecord) : 'GENESIS';
    this.initialized = true;
  }

  private advanceChain(record: AuditRecord): void {
    this.lastRecordHash = hashAuditRecord(record);
    this.initialized = true;
  }

  private async buildQueryRecord(entry: AuditEntry, signer: AgentSigner): Promise<AuditRecord> {
    const record: Omit<AuditRecord, 'signature'> = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      agentDid: entry.agentDid,
      ownerDid: entry.ownerDid,
      credentialId: hashCredential(entry.credentialJwt),
      queryHash: hashQuery(entry.sql),
      columnsAccessed: entry.columnsAccessed,
      rowCount: entry.rowCount,
      durationMs: entry.durationMs,
      previousHash: this.lastRecordHash,
      version: 3,
      status: 'success',
      orgId: entry.orgId,
    };

    return { ...record, signature: await signAuditRecord(record, signer) };
  }

  private async buildRejectionRecord(
    reason: string,
    reasonCode: string,
    signer?: AgentSigner,
    context?: { agentDid?: string; ownerDid?: string; sql?: string; orgId?: string },
  ): Promise<AuditRecord> {
    const record: Omit<AuditRecord, 'signature'> = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      agentDid: context?.agentDid ?? 'unknown',
      ownerDid: context?.ownerDid ?? 'unknown',
      credentialId: 'none',
      queryHash: context?.sql ? hashQuery(context.sql) : 'none',
      columnsAccessed: [],
      rowCount: 0,
      durationMs: 0,
      previousHash: this.lastRecordHash,
      version: 3,
      status: 'rejected',
      reason,
      reasonCode,
      orgId: context?.orgId,
    };

    return { ...record, signature: signer ? await signAuditRecord(record, signer) : 'unsigned' };
  }

  private async appendBuiltRecord(
    operation: 'query' | 'rejection',
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
    operation: 'query' | 'rejection',
    err: unknown,
    _fullRecord?: AuditRecord,
    _buildRecord?: () => Promise<AuditRecord>,
  ): AuditRecord {
    const reason = err instanceof Error ? err.message : 'Unknown error';
    this.emitAuditWriteFailedTelemetry({ operation, error: err });
    throw new AuditWriteFailedError(reason);
  }

  /**
   * Load the last record hash from the DB to maintain chain continuity across restarts.
   * Stores implementing appendWithChainLock() don't need this — they load lazily per-append.
   */
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
      // Table may not exist yet — start with GENESIS
      this.setChainHead(null);
    }
  }

  /** Serialize a chain operation through the mutex. */
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

  /**
   * Log an audit record for a successful agent query.
   * Signs the record with the agent's opaque signer and inserts into agent_audit.
   */
  async log(entry: AuditEntry, signer: AgentSigner): Promise<AuditRecord> {
    return this.withChainLock(async () => {
      return this.appendBuiltRecord('query', () => this.buildQueryRecord(entry, signer));
    });
  }

  /**
   * Log a rejection audit record. Called from the scope-engine so SDK consumers
   * without an HTTP server still get rejection audit trails.
   *
   * `signer` is optional — some rejections occur before agent identity is established.
   * Unsigned records are still hash-chained.
   */
  async logRejection(
    reason: string,
    reasonCode: string,
    signer?: AgentSigner,
    context?: { agentDid?: string; ownerDid?: string; sql?: string; orgId?: string },
  ): Promise<AuditRecord> {
    return this.withChainLock(async () => {
      return this.appendBuiltRecord(
        'rejection',
        () => this.buildRejectionRecord(reason, reasonCode, signer, context),
      );
    });
  }

  /**
   * Verify an audit record's signature using the agent's public key.
   * Can be done offline — only needs the record and the agent's DID.
   */
  async verifyRecord(record: AuditRecord, agentPublicKey: Uint8Array): Promise<boolean> {
    try {
      return await verifyJwtSignature(record.signature, agentPublicKey);
    } catch {
      return false;
    }
  }

  /**
   * Verify hash chain integrity. Without a filter, the first record must have
   * `previousHash === 'GENESIS'` (returns `partial: false`). With a filter,
   * anchors at the first returned record (returns `partial: true`).
   *
   * For `agentDid`/`orgId` filters, apparent breaks may reflect non-consecutive
   * records rather than tampering — call without filters for root-of-chain proof.
   *
   * Does NOT verify Ed25519 signatures — use `verifyRecord()` for that.
   * Cannot detect deleted rows — a dropped record silently re-anchors the chain.
   */
  async verifyAuditChain(filter?: Pick<AuditQueryFilter, 'agentDid' | 'since' | 'orgId'>): Promise<{
    ok: boolean;
    totalRecords: number;
    /** true when a filter was applied — chain is rooted at first returned record, not GENESIS */
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

  /**
   * Export audit records. When an alias registry is set, a single agentDid filter
   * is expanded to all equivalent DIDs to preserve continuity across identity migrations.
   *
   * orgId is forwarded in the expanded query — without it, cross-org aliases would
   * surface records from unintended orgs in org-scoped compliance queries.
   */
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
