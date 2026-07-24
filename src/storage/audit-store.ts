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

import type { AuditRecord } from '#types/audit.js';

/** Filters accepted by AuditStore.query() and AuditStore.count(). */
export interface AuditQueryFilter {
  id?: string;
  agentDid?: string;
  /**
   * Alias-aware DID filter. Takes precedence over agentDid when both are set.
   */
  agentDids?: string[];
  since?: Date;
  /** Human owner DID recorded on each audit event. */
  ownerDid?: string;
  /** Exact credential hash or JTI. */
  credentialId?: string;
  /**
   * Organization ID predicate. Callers must authorize access to the requested
   * organization before invoking the store.
   */
  orgId?: string;
  /** Maximum records returned by the storage query. */
  limit?: number;
}

/**
 * Append-only audit persistence. The absence of mutation methods, database
 * triggers, and hash chaining jointly enforce tamper evidence.
 */
export interface AuditStore {
  /**
   * Persists a fully populated record without generating IDs or hashes.
   * @throws {AuditWriteFailedError} On persistence failure.
   */
  append(record: AuditRecord): Promise<void>;

  /**
   * Atomically append a hash-chained audit record.
   *
   * The chain-head read and append share one lock to prevent concurrent writers
   * from forking the chain. Optional for legacy and test stores.
   */
  appendWithChainLock?(
    buildRecord: (lastRecord: AuditRecord | null) => AuditRecord | Promise<AuditRecord>,
  ): Promise<AuditRecord>;

  /** Loads the chain head, or null for the genesis state. */
  loadLastRecord(): Promise<AuditRecord | null>;

  /**
   * Loads the chain head under a database lock for legacy stores. The lock does
   * not protect a later append, so production writes use appendWithChainLock().
   */
  loadLastRecordLocked(): Promise<AuditRecord | null>;

  /** Queries records ordered by timestamp ascending. */
  query(filter?: AuditQueryFilter): Promise<AuditRecord[]>;

  count(filter?: AuditQueryFilter): Promise<number>;
}
