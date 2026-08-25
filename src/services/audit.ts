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

import { hashAuditRecord } from '#audit/index.js';
import type { AuditQueryFilter } from '#storage/types.js';
import { RequestValidationError } from '#transport/errors.js';
import type { AuditRecord } from '#types/audit.js';
import type { VerificationResult } from '#types/verification.js';

const AUDIT_EXPORT_DEFAULT_LIMIT = 100;
const AUDIT_EXPORT_MAX_LIMIT = 1000;
const AUDIT_RECENT_DEFAULT_LIMIT = 50;

export interface AuditReader {
  export(filter?: AuditQueryFilter): Promise<AuditRecord[]>;
}

export interface AuditVerifier {
  verify(auditRecord: AuditRecord): Promise<VerificationResult>;
}

export interface AuditService {
  exportAudit(
    input?: { agentDid?: string; since?: Date; orgId?: string; limit?: number },
    context?: { ownerDid?: string; orgId?: string },
  ): Promise<{ records: AuditRecord[]; count: number }>;
  /** Return the newest audit records while preserving chronological order. */
  getRecentAudit?(input?: { limit?: number }): Promise<{ records: AuditRecord[]; count: number }>;
  verifyAudit(
    input: { auditId: string },
    context?: { ownerDid?: string; orgId?: string },
  ): Promise<
    | {
        verified: boolean;
        status: VerificationResult['status'];
        record: AuditRecord;
        agentDid: string;
      }
    | { error: 'NOT_FOUND'; message: string }
  >;
  verifyChain(
    input?: { limit?: number },
    context?: { ownerDid?: string; orgId?: string },
  ): Promise<{
    verified: boolean;
    recordsChecked: number;
    brokenLinks: Array<{ index: number; recordId: string; expected: string; actual: string }>;
  }>;
}

export function createAuditService(deps: {
  auditReader: AuditReader;
  verifier: AuditVerifier;
}): AuditService {
  return {
    async exportAudit(input = {}, context = {}) {
      const maxRecords = boundedLimit(
        input.limit,
        AUDIT_EXPORT_DEFAULT_LIMIT,
        AUDIT_EXPORT_MAX_LIMIT,
      );
      const filter: AuditQueryFilter = { limit: maxRecords };
      if (input.agentDid) filter.agentDid = input.agentDid;
      if (input.since) filter.since = input.since;
      if (context.ownerDid) filter.ownerDid = context.ownerDid;
      const orgId = input.orgId ?? context.orgId;
      if (orgId) filter.orgId = orgId;

      assertBoundedAuditQuery(filter);
      const records = await deps.auditReader.export(filter);
      return { records, count: records.length };
    },

    async getRecentAudit(input = {}) {
      const maxRecords = boundedLimit(
        input.limit,
        AUDIT_RECENT_DEFAULT_LIMIT,
        AUDIT_EXPORT_MAX_LIMIT,
      );
      const records = await deps.auditReader.export();
      const recent = records.slice(-maxRecords);
      return { records: recent, count: recent.length };
    },

    async verifyAudit(input, context = {}) {
      const records = await deps.auditReader.export({
        id: input.auditId,
        ownerDid: context.ownerDid,
        orgId: context.orgId,
        limit: 1,
      });
      const record = records.find(
        (candidate) =>
          candidate.id === input.auditId &&
          (!context.ownerDid || candidate.ownerDid === context.ownerDid) &&
          (!context.orgId || candidate.orgId === context.orgId),
      );

      if (!record) {
        return {
          error: 'NOT_FOUND' as const,
          message: `Audit record ${input.auditId} not found`,
        };
      }

      const result = await deps.verifier.verify(record);
      return {
        verified: result.valid,
        status: result.status,
        record,
        agentDid: record.agentDid,
      };
    },

    async verifyChain(input = {}, context = {}) {
      const maxRecords = boundedLimit(input.limit, AUDIT_EXPORT_MAX_LIMIT, AUDIT_EXPORT_MAX_LIMIT);
      const filter: AuditQueryFilter = {
        ownerDid: context.ownerDid,
        orgId: context.orgId,
        limit: maxRecords,
      };
      assertBoundedAuditQuery(filter);
      const bounded = await deps.auditReader.export(filter);

      const brokenLinks: Array<{
        index: number;
        recordId: string;
        expected: string;
        actual: string;
      }> = [];
      let previousHash = 'GENESIS';

      for (let i = 0; i < bounded.length; i++) {
        const record = bounded[i];
        if (record.previousHash !== previousHash) {
          brokenLinks.push({
            index: i,
            recordId: record.id,
            expected: previousHash,
            actual: record.previousHash,
          });
        }
        previousHash = hashAuditRecord({
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
          version: record.version ?? 1,
          status: record.status,
          reason: record.reason,
          reasonCode: record.reasonCode,
          orgId: record.orgId,
        });
      }

      return {
        verified: brokenLinks.length === 0,
        recordsChecked: bounded.length,
        brokenLinks,
      };
    },
  };
}

function boundedLimit(value: number | undefined, defaultValue: number, max: number): number {
  const candidate = value ?? defaultValue;
  if (!Number.isFinite(candidate) || candidate < 1) return defaultValue;
  return Math.min(Math.trunc(candidate), max);
}

function assertBoundedAuditQuery(filter: AuditQueryFilter): void {
  if (
    filter.id ||
    filter.agentDid ||
    (filter.agentDids && filter.agentDids.length > 0) ||
    filter.since ||
    filter.ownerDid ||
    filter.credentialId ||
    filter.orgId
  ) {
    return;
  }

  throw new RequestValidationError([{ path: 'audit', code: 'bounded_filter_required' }]);
}
