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

import type { AuditRecord } from '../types.js';

/**
 * Filter options for AuditStore.query().
 * Matches the existing AuditLogger.export() filter shape.
 */
export interface AuditQueryFilter {
  /**
   * Exact audit record ID lookup.
   *
   * Used by public verification routes so a request for one record stays a
   * single-row storage query instead of exporting the audit table and searching
   * in process memory.
   */
  id?: string;
  agentDid?: string;
  /**
   * Query audit records across multiple DIDs (alias-aware).
   * When a DID migration has occurred, the caller passes both the old and new
   * DIDs so the query returns records from both the pre- and post-migration
   * periods. Takes precedence over agentDid when both are set.
   */
  agentDids?: string[];
  since?: Date;
  /**
   * Filter by the human owner DID recorded on each audit event.
   *
   * REST and MCP user-facing routes are owner-scoped by the authenticated
   * session. Applying that predicate in the store preserves the trust boundary
   * even when the audit table grows large; in-memory owner filtering is retained
   * only as a defense-in-depth check by callers that need it.
   */
  ownerDid?: string;
  /**
   * Exact credential hash/JTI lookup.
   *
   * Credential revocation uses this to prove the requested credential belongs
   * to the caller without scanning unrelated audit records.
   */
  credentialId?: string;
  /**
   * Filter by AbaxxOne parent instance organization ID.
   *
   * Enables per-organization audit queries for compliance reporting and
   * multi-tenant isolation. An AbaxxOne tenant admin can pull all audit
   * records belonging to their organization without scanning the full
   * table. The org_id column is indexed (migration 006) for this purpose.
   *
   * Security note: the caller must verify the requesting user has authority
   * over the orgId being queried. This filter does not perform authorization
   * — it is a data-level query predicate. Authorization belongs in the API
   * layer (REST server or MCP handler) that calls AuditLogger.export().
   */
  orgId?: string;
  /**
   * Maximum records returned by the storage query.
   *
   * Public transports cap this before calling the store. Keeping the limit in
   * the storage filter makes the database enforce the bound with LIMIT instead
   * of relying on post-query array slicing after a broad export.
   */
  limit?: number;
}

/**
 * AuditStore — append-only interface for the audit trail.
 *
 * Security decision: this interface has NO update() or delete() methods. The
 * append-only invariant is enforced at three levels:
 *   1. Interface design — no mutation methods exist to call
 *   2. Database triggers — BEFORE UPDATE/DELETE triggers raise errors
 *      (Postgres: existing in 001_init.sql; SQLite: created by migrations.ts)
 *   3. Hash chaining — each record includes SHA-256 of the previous record,
 *      making retroactive tampering detectable even if triggers are bypassed
 *
 * Server-internal: called by AuditLogger after query verification. No
 * IdentityContext parameter.
 */
export interface AuditStore {
  /**
   * Append an audit record. The record must already have all fields populated
   * (including id, timestamp, signature, previousHash). The store only persists;
   * it does not generate IDs or compute hashes — that logic stays in AuditLogger.
   *
   * Throws AuditWriteFailedError on persistence failure.
   */
  append(record: AuditRecord): Promise<void>;

  /**
   * Atomically append a hash-chained audit record.
   *
   * Security rationale: the chain head read and the append must happen under
   * the same store-level lock/transaction. A separate loadLastRecordLocked()
   * followed by append() still lets two processes read the same head before
   * either write commits, forking the audit chain. Production stores implement
   * this hook so AuditLogger can build the signed record from the locked head
   * and persist it before releasing the lock.
   *
   * Optional for legacy/test stores; AuditLogger falls back to
   * loadLastRecordLocked()+append() when absent.
   */
  appendWithChainLock?(
    buildRecord: (lastRecord: AuditRecord | null) => AuditRecord,
  ): Promise<AuditRecord>;

  /**
   * Load the last audit record for hash chain initialization.
   * Returns null if no records exist (GENESIS state).
   *
   * Called once on startup by AuditLogger.initialize() to restore the
   * hash chain across process restarts. O(1) — queries by timestamp DESC LIMIT 1.
   */
  loadLastRecord(): Promise<AuditRecord | null>;

  /**
   * Load the last audit record while holding a DB-level exclusive lock to
   * prevent concurrent init from two processes reading the same chain head
   * and producing a forked hash chain.
   *
   * Implementations:
   *   - Postgres: pg_advisory_xact_lock(hashCode) inside a transaction, then
   *     SELECT ... ORDER BY timestamp DESC LIMIT 1. Lock is held until the
   *     transaction commits.
   *   - SQLite: BEGIN IMMEDIATE acquires a RESERVED lock on the database,
   *     preventing any other writer from starting until the read completes.
   *     BEGIN IMMEDIATE acquires the write lock at BEGIN time, not at first
   *     write statement (which is what BEGIN DEFERRED does and why that
   *     leaves the race open).
   *
   * Called by AuditLogger.initialize() for legacy/test stores. Production
   * AuditLogger writes prefer appendWithChainLock(), because serializing only
   * this read does not protect the later append.
   */
  loadLastRecordLocked(): Promise<AuditRecord | null>;

  /**
   * Query audit records with optional filters. Ordered by timestamp ASC.
   * Used by AuditLogger.export() for offline verification.
   */
  query(filter?: AuditQueryFilter): Promise<AuditRecord[]>;

  /**
   * Count audit records, optionally filtered by AuditQueryFilter fields.
   *
   * O(1) on indexed tables. Used for compliance reporting (total audit events
   * per org/agent), dashboard stats, and pagination metadata. Reuses the same
   * AuditQueryFilter type as query() for filter consistency.
   */
  count(filter?: AuditQueryFilter): Promise<number>;
}
