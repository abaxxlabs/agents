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

import type { IdentityContext } from './identity-context-types.js';

/**
 * Domain-neutral JSON document owned by an agent DID. The server identity may
 * bypass ownership checks for trusted administrative operations.
 */
export interface ContextEntry {
  /** Consumer-defined logical partition. */
  namespace: string;
  /** Entry ID within the namespace. Caller-defined (UUID, slug, etc.). */
  key: string;
  /** Opaque JSON-serializable payload. */
  value: Record<string, unknown>;
  /** Agent DID that owns this entry. Set on creation, immutable. */
  ownerDid: string;
  /** ISO 8601 timestamp when this entry was first created. */
  createdAt: string;
  /** ISO 8601 timestamp of the most recent update. */
  updatedAt: string;
}

/** Pagination options for ContextStore.list(). */
export interface ContextListOptions {
  limit?: number; // default: 100
  offset?: number; // default: 0
}

/**
 * Identity-gated document persistence. Implementations enforce ownership in
 * storage queries; server identity means callerDid equals issuerDid.
 */
export interface ContextStore {
  /**
   * Creates or updates an entry owned by the caller or server identity.
   * @throws {Error} if ownerDid does not match callerDid and caller is not server.
   */
  put(
    entry: Omit<ContextEntry, 'createdAt' | 'updatedAt'>,
    identity: IdentityContext,
  ): Promise<ContextEntry>;

  /**
   * Reads an entry by namespace and key. Missing and unauthorized entries both
   * return null to prevent existence enumeration.
   */
  get(namespace: string, key: string, identity: IdentityContext): Promise<ContextEntry | null>;

  /** Lists caller-owned entries, or all entries for server identity. */
  list(
    namespace: string,
    identity: IdentityContext,
    options?: ContextListOptions,
  ): Promise<ContextEntry[]>;

  /**
   * Deletes an entry. Missing and unauthorized entries both return false to
   * prevent existence enumeration.
   */
  delete(namespace: string, key: string, identity: IdentityContext): Promise<boolean>;
}
