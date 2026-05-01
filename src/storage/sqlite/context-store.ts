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
 * SqliteContextStore — SQLite implementation of ContextStore.
 *
 * SQLite adaptations: value as JSON TEXT, ISO 8601 timestamps, upsert via
 * INSERT ... ON CONFLICT DO UPDATE, synchronous calls wrapped async.
 * Server identity bypass (callerDid === issuerDid) skips owner_did filter.
 */

import type { Database, RunResult } from 'better-sqlite3';
import type { ContextStore, ContextEntry, ContextListOptions, IdentityContext } from '../types.js';

interface ContextRow {
  namespace: string;
  key: string;
  value: string;
  owner_did: string;
  created_at: string;
  updated_at: string;
}

interface ContextExistingRow {
  owner_did: string;
  created_at: string;
}

export class SqliteContextStore implements ContextStore {
  private readonly db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  async put(
    entry: Omit<ContextEntry, 'createdAt' | 'updatedAt'>,
    identity: IdentityContext,
  ): Promise<ContextEntry> {
    const isServer = identity.callerDid === identity.issuerDid;
    if (!isServer && entry.ownerDid !== identity.callerDid) {
      throw new Error(
        `Context store access denied: callerDid '${identity.callerDid}' does not match ` +
          `entry ownerDid '${entry.ownerDid}'. Only the owner or server may write entries.`,
      );
    }

    const now = new Date().toISOString();
    const valueJson = JSON.stringify(entry.value);

    // Check if entry exists and verify ownership for updates.
    const existing = this.db
      .prepare('SELECT owner_did, created_at FROM agent_context WHERE namespace = ? AND key = ?')
      .get(entry.namespace, entry.key) as ContextExistingRow | undefined;

    if (existing) {
      // Update path: verify ownership.
      if (!isServer && existing.owner_did !== identity.callerDid) {
        throw new Error(
          `Context store access denied: entry '${entry.namespace}/${entry.key}' is owned by ` +
            `a different agent. Only the original owner may update it.`,
        );
      }

      this.db
        .prepare(
          `UPDATE agent_context SET value = ?, updated_at = ?
         WHERE namespace = ? AND key = ?`,
        )
        .run(valueJson, now, entry.namespace, entry.key);

      return {
        namespace: entry.namespace,
        key: entry.key,
        value: entry.value,
        ownerDid: entry.ownerDid,
        createdAt: existing.created_at,
        updatedAt: now,
      };
    }

    // Insert path: new entry.
    this.db
      .prepare(
        `INSERT INTO agent_context (namespace, key, value, owner_did, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(entry.namespace, entry.key, valueJson, entry.ownerDid, now, now);

    return {
      namespace: entry.namespace,
      key: entry.key,
      value: entry.value,
      ownerDid: entry.ownerDid,
      createdAt: now,
      updatedAt: now,
    };
  }

  async get(
    namespace: string,
    key: string,
    identity: IdentityContext,
  ): Promise<ContextEntry | null> {
    const isServer = identity.callerDid === identity.issuerDid;

    let row: ContextRow | undefined;
    if (isServer) {
      row = this.db
        .prepare(
          `SELECT namespace, key, value, owner_did, created_at, updated_at
         FROM agent_context WHERE namespace = ? AND key = ?`,
        )
        .get(namespace, key) as ContextRow | undefined;
    } else {
      row = this.db
        .prepare(
          `SELECT namespace, key, value, owner_did, created_at, updated_at
         FROM agent_context WHERE namespace = ? AND key = ? AND owner_did = ?`,
        )
        .get(namespace, key, identity.callerDid) as ContextRow | undefined;
    }

    if (!row) return null;

    return {
      namespace: row.namespace,
      key: row.key,
      value: typeof row.value === 'string' ? JSON.parse(row.value) : row.value,
      ownerDid: row.owner_did,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async list(
    namespace: string,
    identity: IdentityContext,
    options?: ContextListOptions,
  ): Promise<ContextEntry[]> {
    const isServer = identity.callerDid === identity.issuerDid;
    const limit = Math.min(options?.limit ?? 100, 1000);
    const offset = options?.offset ?? 0;

    let rows: ContextRow[];
    if (isServer) {
      rows = this.db
        .prepare(
          `SELECT namespace, key, value, owner_did, created_at, updated_at
         FROM agent_context WHERE namespace = ?
         ORDER BY created_at ASC LIMIT ? OFFSET ?`,
        )
        .all(namespace, limit, offset) as ContextRow[];
    } else {
      rows = this.db
        .prepare(
          `SELECT namespace, key, value, owner_did, created_at, updated_at
         FROM agent_context WHERE namespace = ? AND owner_did = ?
         ORDER BY created_at ASC LIMIT ? OFFSET ?`,
        )
        .all(namespace, identity.callerDid, limit, offset) as ContextRow[];
    }

    return rows.map((row) => ({
      namespace: row.namespace,
      key: row.key,
      value: typeof row.value === 'string' ? JSON.parse(row.value) : row.value,
      ownerDid: row.owner_did,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  async delete(namespace: string, key: string, identity: IdentityContext): Promise<boolean> {
    const isServer = identity.callerDid === identity.issuerDid;

    let result: RunResult;
    if (isServer) {
      result = this.db
        .prepare('DELETE FROM agent_context WHERE namespace = ? AND key = ?')
        .run(namespace, key);
    } else {
      result = this.db
        .prepare('DELETE FROM agent_context WHERE namespace = ? AND key = ? AND owner_did = ?')
        .run(namespace, key, identity.callerDid);
    }

    return result.changes > 0;
  }
}
