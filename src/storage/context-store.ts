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
 * ContextEntry — a generic, identity-gated document in the context store.
 *
 * Designed to be domain-agnostic: agents defines the schema and gating;
 * consumers (Chief, etc.) define the semantics of what goes in `value`.
 *
 * The namespace+key pair forms a composite primary key. Chief uses namespace
 * "context-graph" with keys like "decision:uuid", "blocker:uuid". Other
 * consumers can use different namespaces without collision.
 *
 * Identity gating: ownerDid is the agent DID that created the entry.
 * ContextStore enforces that only the ownerDid can read/write/delete the entry,
 * with a server-identity bypass (callerDid === issuerDid) for admin/export.
 */
export interface ContextEntry {
  /** Logical partition for multi-tenant use ("context-graph", "sessions", etc.). */
  namespace: string;
  /** Entry ID within the namespace. Caller-defined (UUID, slug, etc.). */
  key: string;
  /** JSON-serializable payload. Agent-id stores it opaquely. */
  value: Record<string, unknown>;
  /** Agent DID that owns this entry. Set on creation, immutable. */
  ownerDid: string;
  /** ISO 8601 timestamp when this entry was first created. */
  createdAt: string;
  /** ISO 8601 timestamp of the most recent update. */
  updatedAt: string;
}

/**
 * Options for ContextStore.list().
 */
export interface ContextListOptions {
  limit?: number; // default: 100
  offset?: number; // default: 0
}

/**
 * ContextStore — identity-gated generic document store.
 *
 * The external-facing storage interface. Chief's children (untrusted agents)
 * interact with this via MCP tools. Every operation requires an IdentityContext
 * to enforce access control.
 *
 * Identity gating rules:
 *   - put(): ownerDid in the entry must match identity.callerDid. The server
 *     identity (callerDid === issuerDid) may write on behalf of any agent.
 *   - get(): only the ownerDid may read the entry. Server identity bypass.
 *   - list(): returns only entries where ownerDid === identity.callerDid.
 *     Server identity returns all entries in the namespace.
 *   - delete(): only the ownerDid may delete. Server identity bypass.
 *
 * The "server identity bypass" pattern: when the caller IS the server itself
 * (callerDid === issuerDid), it is the trusted zone performing admin operations
 * (export, backup, context injection). This bypass is safe because the server
 * holds the private key material — it could write arbitrary records anyway.
 *
 * Enforcement is at the query level (WHERE owner_did = $callerDid), not
 * middleware. This means even a bug in the calling code that passes the wrong
 * IdentityContext will not leak data — the database enforces the boundary.
 */
export interface ContextStore {
  /**
   * Write a context entry. Upsert semantics: creates on first write,
   * updates on subsequent writes to the same namespace+key.
   *
   * Identity gating: entry.ownerDid must match identity.callerDid,
   * or identity must be server identity (callerDid === issuerDid).
   *
   * @throws {Error} if ownerDid does not match callerDid and caller is not server.
   */
  put(
    entry: Omit<ContextEntry, 'createdAt' | 'updatedAt'>,
    identity: IdentityContext,
  ): Promise<ContextEntry>;

  /**
   * Read a context entry by namespace + key.
   * Returns null if not found OR if the caller lacks access.
   *
   * Security note: returning null for access-denied (rather than throwing) is
   * intentional — it prevents enumeration attacks where an attacker probes
   * namespace+key combinations and uses error vs. null to infer existence.
   */
  get(namespace: string, key: string, identity: IdentityContext): Promise<ContextEntry | null>;

  /**
   * List entries in a namespace. Returns only entries the caller owns.
   * Server identity returns all entries in the namespace.
   */
  list(
    namespace: string,
    identity: IdentityContext,
    options?: ContextListOptions,
  ): Promise<ContextEntry[]>;

  /**
   * Delete a context entry. Returns true if deleted, false if not found
   * or caller lacks access.
   *
   * Same null/false ambiguity as get() — prevents existence enumeration.
   */
  delete(namespace: string, key: string, identity: IdentityContext): Promise<boolean>;
}
