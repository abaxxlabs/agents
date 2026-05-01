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
 * AgentRecord — a registered agent in the agents table.
 *
 * Maps 1:1 to the agents schema:
 *   did TEXT PRIMARY KEY → did
 *   name TEXT NOT NULL → name
 *   owner_did TEXT NOT NULL → ownerDid
 *   created_at TIMESTAMPTZ DEFAULT NOW() → createdAt
 */
export interface AgentRecord {
  did: string;
  name: string;
  ownerDid: string;
  createdAt: string; // ISO 8601
  /** AES-256-GCM wrapped Ed25519 private key (null/undefined if created before key persistence). */
  encryptedPrivateKey?: Buffer | null;
  /** Raw Ed25519 public key bytes (null/undefined if created before key persistence). */
  publicKey?: Buffer | null;
}

/**
 * Filter options for AgentStore.list().
 */
export interface AgentListFilter {
  ownerDid?: string;
  limit?: number; // default: 100, max: 100
}

/**
 * AgentStore — CRUD interface for the agent registry.
 *
 * Server-internal: called by the auth module after AgentVerifier has already
 * verified the requesting human/agent. No IdentityContext parameter — the
 * trust boundary is at the MCP layer, not the storage layer.
 *
 * Maps to the agents table (Postgres) or equivalent (SQLite).
 */
export interface AgentStore {
  /**
   * Register a new agent. Throws on duplicate DID.
   * createdAt is set by the implementation (current timestamp).
   */
  create(agent: Omit<AgentRecord, 'createdAt'>): Promise<AgentRecord>;

  /**
   * Find an agent by DID. Returns null if not found.
   * Must not throw on missing agent — return null instead.
   */
  findByDid(did: string): Promise<AgentRecord | null>;

  /**
   * List agents with optional filters.
   * Default limit: 100. Max limit: 100 (capped by implementation).
   */
  list(filter?: AgentListFilter): Promise<AgentRecord[]>;

  /**
   * Load all registered agents, unbounded.
   *
   * Used by restoreAgents() to reload agents into memory at boot. Returns every
   * row in the agents table without pagination. For deployments with >1000
   * agents, consider implementing batched restore.
   *
   * Architectural note: listAll() exists separately from list() because list()
   * is designed for API-facing use with mandatory caps (limit <= 100). Boot-time
   * restore needs the full set without artificial caps. Keeping them separate
   * prevents accidental removal of the API-facing limit guard.
   */
  listAll(): Promise<AgentRecord[]>;

  /**
   * Count registered agents, optionally filtered by ownerDid.
   *
   * O(1) on indexed tables. Used for dashboard stats, pagination metadata,
   * and capacity checks before batch operations.
   */
  count(filter?: { ownerDid?: string }): Promise<number>;
}
