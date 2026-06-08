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
 * Transport-neutral service layer shared by REST and MCP adapters.
 *
 * Authorization, audit filtering, row caps, and response shaping live here so
 * they stay consistent across transports. SQL enforcement remains in ScopeEngine.
 * Telemetry hooks are optional and one-way — they cannot alter service behavior.
 */

import { hashAuditRecord } from '#audit/index.js';
import { assertScopeFitsInCeiling, type ScopeCeiling } from '#auth/ceiling.js';
import { RequestValidationError } from '#transport/errors.js';
import type {
  AuthenticatedSession,
  CreateAgentOptions,
  RegisteredAgent,
} from '#types/auth.js';
import type {
  DelegateCredentialOptions,
  IssueCredentialOptions,
} from '#types/credential.js';
import type { AuditRecord } from '#types/audit.js';
import type { VerificationResult } from '#types/verification.js';
import type { AuditQueryFilter } from '#storage/types.js';

const AUDIT_EXPORT_DEFAULT_LIMIT = 100;
const AUDIT_EXPORT_MAX_LIMIT = 1000;
const CREDENTIAL_AUDIT_DEFAULT_LIMIT = 500;
const CREDENTIAL_AUDIT_MAX_LIMIT = 1000;

export interface ScopedQueryInput {
  agent: string;
  credential: string;
  sql: string;
  table: string;
  params?: unknown[];
  credentials?: string[];
  requirePresentation?: boolean;
  orgId?: string;
}

export interface ScopedQueryResult {
  rows: Record<string, unknown>[];
  metadata: {
    agent: string;
    owner: string;
    columnsDecrypted: string[];
    columnsEncrypted: string[];
    rowCount: number;
    queryDurationMs: number;
    auditId: string;
  };
}

export interface QueryExecutor {
  query(options: ScopedQueryInput): Promise<ScopedQueryResult>;
}

export interface QueryService {
  execute(input: ScopedQueryInput, context?: { orgId?: string }): Promise<ScopedQueryResult>;
}

export interface QueryServiceTelemetrySink {
  credentialVerification(event: {
    outcome: 'succeeded' | 'failed';
    agentDid: string;
    credentialCount: number;
    error?: unknown;
  }): void;
  queryRejected(event: {
    agentDid: string;
    table: string;
    error: unknown;
  }): void;
  auditWriteFailed(event: {
    agentDid: string;
    table: string;
    error: unknown;
  }): void;
}

export interface AgentDirectory {
  createAgent(options: CreateAgentOptions): Promise<RegisteredAgent>;
  listAgents(filter?: { ownerDid?: string; limit?: number }): Promise<
    Array<{
      did: string;
      name: string;
      ownerDid: string;
      createdAt: string;
    }>
  >;
}

export interface AgentDirectoryService {
  createAgent(options: CreateAgentOptions): Promise<RegisteredAgent>;
  listAgents(filter?: { ownerDid?: string; limit?: number }): Promise<
    Array<{
      did: string;
      name: string;
      ownerDid: string;
      createdAt: string;
    }>
  >;
}

export interface CredentialIssuer {
  issueCredential(options: IssueCredentialOptions): Promise<string>;
}

export interface CredentialRevoker {
  revokeCredential(credentialId: string): ReturnType<AuthenticatedSession['revokeCredential']>;
}

export interface CredentialDelegator {
  delegateCredential(
    sourceAgentDid: string,
    sourceCredential: string,
    options: DelegateCredentialOptions,
  ): Promise<string>;
}

export interface AuditReader {
  export(filter?: AuditQueryFilter): Promise<AuditRecord[]>;
}

export interface AuditVerifier {
  verify(auditRecord: AuditRecord): Promise<VerificationResult>;
}

export interface CredentialService {
  issueCredential(
    input: IssueCredentialOptions,
  ): Promise<{ credential: string; jti?: unknown; exp?: unknown }>;
  delegateCredential(
    input: {
      sourceAgentDid: string;
      sourceCredential: string;
      targetAgent: string;
      columns: string[];
      actions: string[];
      expiresIn: string | number;
    },
    context?: { scopeCeiling?: ScopeCeiling },
  ): Promise<{ credential: string }>;
  listCredentials(
    input: { agentDid?: string; issuedAfter?: Date; limit?: number },
    context: { ownerDid: string },
  ): Promise<{
    credentials: Array<{
      credentialId: string;
      agentDid: string;
      ownerDid: string;
      issuedAt: string;
    }>;
    count: number;
  }>;
  revokeCredential(
    input: { credentialId: string },
    context: { ownerDid: string },
  ): Promise<{ revoked: true; credentialId: string; sdkNotificationFailed?: string }>;
}

export interface AuditService {
  exportAudit(
    input?: { agentDid?: string; since?: Date; orgId?: string; limit?: number },
    context?: { ownerDid?: string; orgId?: string },
  ): Promise<{ records: AuditRecord[]; count: number }>;
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

export interface AgentToolServices {
  query: QueryService;
  agents: AgentDirectoryService;
  credentials: CredentialService;
  audit: AuditService;
}

export function createQueryService(deps: {
  executor: QueryExecutor;
  maxRows?: number;
  telemetry?: QueryServiceTelemetrySink;
}): QueryService {
  const maxRows = deps.maxRows ?? 1000;
  return {
    async execute(input, context) {
      let result: ScopedQueryResult;
      try {
        result = await deps.executor.query({
          ...input,
          orgId: context?.orgId ?? input.orgId,
        });
      } catch (err) {
        const code = errorCode(err);
        if (isCredentialVerificationCode(code)) {
          emitQueryTelemetry(deps.telemetry, 'credentialVerification', {
            outcome: 'failed',
            agentDid: input.agent,
            credentialCount: credentialCount(input),
            error: err,
          });
        }
        if (isQueryRejectionCode(code)) {
          emitQueryTelemetry(deps.telemetry, 'queryRejected', {
            agentDid: input.agent,
            table: input.table,
            error: err,
          });
        }
        if (code === 'AUDIT_WRITE_FAILED') {
          emitQueryTelemetry(deps.telemetry, 'auditWriteFailed', {
            agentDid: input.agent,
            table: input.table,
            error: err,
          });
        }
        throw err;
      }

      emitQueryTelemetry(deps.telemetry, 'credentialVerification', {
        outcome: 'succeeded',
        agentDid: input.agent,
        credentialCount: credentialCount(input),
      });

      if (result.rows.length > maxRows) {
        return {
          ...result,
          rows: result.rows.slice(0, maxRows),
          metadata: {
            ...result.metadata,
            rowCount: maxRows,
          },
        };
      }

      return result;
    },
  };
}

export function createAgentDirectoryService(deps: {
  agents: AgentDirectory;
}): AgentDirectoryService {
  return {
    createAgent(options) {
      return deps.agents.createAgent(options);
    },
    listAgents(filter) {
      return deps.agents.listAgents(filter);
    },
  };
}

export function createCredentialService(deps: {
  issuer: CredentialIssuer;
  revoker: CredentialRevoker;
  delegator: CredentialDelegator;
  auditReader: AuditReader;
}): CredentialService {
  return {
    async issueCredential(input) {
      const credential = await deps.issuer.issueCredential(input);
      const [, payloadB64] = credential.split('.');
      const jwtPayload = payloadB64
        ? (JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8')) as Record<
            string,
            unknown
          >)
        : {};
      return { credential, jti: jwtPayload.jti, exp: jwtPayload.exp };
    },

    async delegateCredential(input, context) {
      if (context?.scopeCeiling) {
        assertScopeFitsInCeiling(
          { columns: input.columns, actions: input.actions },
          context.scopeCeiling,
        );
      }

      const credential = await deps.delegator.delegateCredential(
        input.sourceAgentDid,
        input.sourceCredential,
        {
          targetAgent: input.targetAgent,
          columns: input.columns,
          actions: input.actions as 'read'[],
          expiresIn: input.expiresIn,
        },
      );
      return { credential };
    },

    async listCredentials(input, context) {
      const auditFilter: AuditQueryFilter = {
        ownerDid: context.ownerDid,
        limit: boundedLimit(
          input.limit,
          CREDENTIAL_AUDIT_DEFAULT_LIMIT,
          CREDENTIAL_AUDIT_MAX_LIMIT,
        ),
      };
      if (input.agentDid) auditFilter.agentDid = input.agentDid;
      if (input.issuedAfter) auditFilter.since = input.issuedAfter;

      const records = await deps.auditReader.export(auditFilter);

      const seen = new Map<
        string,
        { credentialId: string; agentDid: string; ownerDid: string; firstSeen: string }
      >();
      for (const record of records) {
        if (record.ownerDid !== context.ownerDid) continue;
        const key = `${record.credentialId}:${record.agentDid}`;
        const existing = seen.get(key);
        if (!existing || record.timestamp < existing.firstSeen) {
          seen.set(key, {
            credentialId: record.credentialId,
            agentDid: record.agentDid,
            ownerDid: record.ownerDid,
            firstSeen: record.timestamp,
          });
        }
      }

      const issuedAfterMs = input.issuedAfter?.getTime();
      const credentials = Array.from(seen.values())
        .filter(
          (credential) =>
            issuedAfterMs === undefined || new Date(credential.firstSeen).getTime() > issuedAfterMs,
        )
        .map((credential) => ({
          credentialId: credential.credentialId,
          agentDid: credential.agentDid,
          ownerDid: credential.ownerDid,
          issuedAt: credential.firstSeen,
        }));

      return { credentials, count: credentials.length };
    },

    async revokeCredential(input, context) {
      const auditRecords = await deps.auditReader.export({
        credentialId: input.credentialId,
        ownerDid: context.ownerDid,
        limit: 1,
      });
      const matchingRecord = auditRecords.find(
        (record) =>
          record.credentialId === input.credentialId && record.ownerDid === context.ownerDid,
      );

      if (!matchingRecord) {
        const err = new Error('Forbidden: credential not found or not issued by this session.');
        (err as Error & { code?: string }).code = 'FORBIDDEN_CREDENTIAL';
        throw err;
      }

      const result = await deps.revoker.revokeCredential(input.credentialId);
      const response: { revoked: true; credentialId: string; sdkNotificationFailed?: string } = {
        revoked: true,
        credentialId: input.credentialId,
      };
      if (result.sdkNotificationFailed) {
        response.sdkNotificationFailed = result.sdkNotificationFailed.message;
      }
      return response;
    },
  };
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

export function createAgentToolServices(deps: {
  queryExecutor: QueryExecutor;
  agentDirectory: AgentDirectory;
  credentialIssuer: CredentialIssuer;
  credentialRevoker: CredentialRevoker;
  credentialDelegator: CredentialDelegator;
  auditReader: AuditReader;
  auditVerifier: AuditVerifier;
  maxQueryRows?: number;
  queryTelemetry?: QueryServiceTelemetrySink;
}): AgentToolServices {
  return {
    query: createQueryService({
      executor: deps.queryExecutor,
      maxRows: deps.maxQueryRows,
      telemetry: deps.queryTelemetry,
    }),
    agents: createAgentDirectoryService({ agents: deps.agentDirectory }),
    credentials: createCredentialService({
      issuer: deps.credentialIssuer,
      revoker: deps.credentialRevoker,
      delegator: deps.credentialDelegator,
      auditReader: deps.auditReader,
    }),
    audit: createAuditService({
      auditReader: deps.auditReader,
      verifier: deps.auditVerifier,
    }),
  };
}

function credentialCount(input: ScopedQueryInput): number {
  return (input.credential ? 1 : 0) + (input.credentials?.length ?? 0);
}

function errorCode(err: unknown): string | undefined {
  return err && typeof err === 'object' && 'code' in err && typeof (err as { code?: unknown }).code === 'string'
    ? (err as { code: string }).code
    : undefined;
}

function isCredentialVerificationCode(code: string | undefined): boolean {
  return code === 'CREDENTIAL_INVALID' ||
    code === 'CREDENTIAL_EXPIRED' ||
    code === 'CREDENTIAL_REVOKED' ||
    code === 'CREDENTIAL_MALFORMED' ||
    code === 'CREDENTIAL_REPLAYED' ||
    code === 'UNKNOWN_ISSUER' ||
    code === 'DID_RESOLUTION_FAILED';
}

function isQueryRejectionCode(code: string | undefined): boolean {
  return code === 'QUERY_REJECTED' || code === 'SCOPE_VIOLATION';
}

function emitQueryTelemetry<K extends keyof QueryServiceTelemetrySink>(
  telemetry: QueryServiceTelemetrySink | undefined,
  method: K,
  event: Parameters<QueryServiceTelemetrySink[K]>[0],
): void {
  try {
    telemetry?.[method](event as never);
  } catch {
    // Operational telemetry is best-effort and must not alter service behavior.
  }
}
