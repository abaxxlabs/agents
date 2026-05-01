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
 * TrustAnchorStore — Layer 2 trust anchor management for MCP agent authorization.
 *
 * Enforces "know your issuer": without this check, any VC issuer — including a
 * compromised or attacker-controlled server — could issue binding VCs that
 * CapabilityEngine would honor.
 *
 * Intentionally NOT injected into VcVerifier (which stays pure/stateless) — enforcement
 * is AgentVerifier, the mandatory single door into MCP auth. Making VcVerifier "smart"
 * about trust would be a compositional trap that makes the security model opaque.
 *
 * TrustAnchorSource types:
 *   'local'  — own server DID. Always trusted. Cannot be removed.
 *   'env'    — DIDs from the `initialTrustedServers` constructor option (consumers call
 *              `resolveTrustedServersFromEnv()` from bootstrap and pass the result here).
 *              Not persisted — re-evaluated on restart.
 *   'api'    — added programmatically. Persisted to keystore across restarts.
 *   'parent' — from a verified AbaxxOne parent credential's `iss` field. NOT persisted —
 *              re-derived each session so trust cannot outlive the credential.
 *
 * Events: 'server-discovered' (TrustAnchor) and 'server-removed' (DID string).
 * Only 'api' anchors are persisted; keystore corruption fails safe to own-DID + env trust only.
 */

import { EventEmitter } from 'node:events';
import type { KeystoreBackend } from '../identity/keystore.js';

// ─── Public Types ─────────────────────────────────────────────────────────────

/**
 * The origin of a trust anchor entry.
 * 'local'/'env'/'parent' are never persisted. 'api' is persisted to the keystore.
 */
export type TrustAnchorSource = 'local' | 'env' | 'api' | 'parent';

/**
 * A single trusted server entry.
 *
 * `did` uniquely identifies the trusted server. `source` describes how this
 * anchor was established. `addedAt` is a Unix timestamp (seconds). `label` is
 * an optional human-readable name for display in the `discover` MCP tool.
 */
export interface TrustAnchor {
  /** The server DID being trusted. */
  did: string;
  /** How this anchor was established. */
  source: TrustAnchorSource;
  /** Unix timestamp (seconds) when this anchor was added. */
  addedAt: number;
  /** Optional human-readable label for display (e.g., in MCP `discover` output). */
  label?: string;
}

// ─── TrustAnchorStore interface ──────────────────────────────────────────────

/**
 * TrustAnchorStore — the public contract for trust anchor management.
 *
 * AgentVerifier depends on this interface (not the concrete class) so tests can
 * inject a stub. The concrete implementation is LocalTrustAnchorStore.
 *
 * @see AgentVerifier — src/identity/agent-verifier.ts
 * @see MCP discover tool — uses list() to report topology
 */
export interface TrustAnchorStore extends EventEmitter {
  /**
   * Add a server DID to the trusted set. Emits 'server-discovered' if the DID
   * is new. Idempotent: if the DID already exists it is overwritten silently
   * (no second 'server-discovered' event).
   *
   * @throws {TypeError} if did is not a non-empty string.
   */
  addTrustedServer(did: string, source: TrustAnchorSource, label?: string): Promise<void>;

  /**
   * Remove a server DID from the trusted set. Emits 'server-removed' if the DID
   * was present. No-op if the DID was not in the set.
   *
   * @throws {Error} if the DID is the own server DID (source: 'local') — cannot
   *   remove the server's own trust anchor.
   */
  removeTrustedServer(did: string): Promise<void>;

  /**
   * Check whether a DID is in the trusted set. O(1).
   *
   * Called on the hot path by AgentVerifier — must not throw, must not block.
   */
  isTrusted(did: string): boolean;

  /**
   * Return all current trust anchors as an array. Used by the MCP `discover` tool
   * to report the server's trust topology.
   *
   * Returns a snapshot — callers must not mutate the returned objects.
   */
  list(): TrustAnchor[];

  /**
   * Persist 'api' source anchors to the keystore. Called automatically by
   * addTrustedServer() and removeTrustedServer() when a keystore is configured.
   * Exposed publicly for explicit flush in shutdown sequences.
   */
  persist(): Promise<void>;

  /**
   * Load persisted 'api' anchors from the keystore. Call once after construction
   * to restore anchors that were added programmatically in a previous run.
   * 'local' and 'env' anchors are already loaded in the constructor.
   */
  load(): Promise<void>;

  /**
   * Add a parent instance's issuer DID as a trust anchor.
   *
   * Parent-issued agent credentials pass verification only after the org's issuer
   * DID is trusted. The parent DID is extracted from the credential chain (not
   * OIDC discovery) — the credential's `iss` field is the source of truth.
   *
   * Security: parent anchors are NOT persisted to the keystore. They are re-derived
   * from the credential chain on each session, ensuring trust cannot outlive the
   * credential that established it. If the parent credential expires or is revoked,
   * the trust anchor disappears on the next session.
   *
   * @param parentDid — the parent instance's issuer DID (must be did:key: or did:dht:)
   * @param label — optional human-readable label for display
   * @throws {TypeError} if parentDid is not a valid DID format
   */
  addParentTrust(parentDid: string, label?: string): Promise<void>;
}

// ─── Keystore key ─────────────────────────────────────────────────────────────

/**
 * Keystore key under which 'api' source anchors are serialized as JSON.
 * Prefixed 'agents:' to avoid collisions with other keystore entries.
 */
const KEYSTORE_KEY = 'agents:trust-anchors';

// ─── LocalTrustAnchorStore ────────────────────────────────────────────────────

/**
 * In-memory + keystore-backed implementation of TrustAnchorStore.
 *
 * Bootstraps with own server DID ('local') and any `initialTrustedServers` ('env').
 * Consumers call `resolveTrustedServersFromEnv()` from `@abaxxlabs/agents/bootstrap`
 * and pass the result — the library does not read `AGENTS_TRUSTED_SERVERS` directly.
 *
 * @fires server-discovered — when a new DID is added (TrustAnchor payload)
 * @fires server-removed    — when a DID is removed (DID string payload)
 */
export class LocalTrustAnchorStore extends EventEmitter implements TrustAnchorStore {
  /** Internal map: DID string → TrustAnchor. Map for O(1) isTrusted(). */
  private readonly _anchors: Map<string, TrustAnchor> = new Map();

  /**
   * The own server's DID. Stored so removeTrustedServer() can enforce the
   * "cannot remove self" invariant without inspecting source field (which could
   * theoretically be overwritten by an api-source entry with the same DID).
   */
  private readonly _ownDid: string;

  /**
   * Optional keystore for persisting 'api' source anchors.
   * If not provided, no persistence occurs — state is in-memory only.
   */
  private readonly _keystore: KeystoreBackend | null;

  /**
   * @param options.ownServerDid — the server's own DID (always trusted, source: 'local').
   * @param options.keystore — optional backend for persisting 'api' anchors across restarts.
   * @param options.initialTrustedServers — pre-trusted DIDs seeded as source='env'.
   *   Own-DID duplicates are silently dropped.
   */
  constructor(options: {
    ownServerDid: string;
    keystore?: KeystoreBackend;
    /**
     * `readonly string[]` for symmetry with the engine-side surfaces and
     * `AgentScopeConfig.orgBoundary.extraConsumerDomains` (also readonly).
     */
    initialTrustedServers?: readonly string[];
  }) {
    super();

    if (!options.ownServerDid || typeof options.ownServerDid !== 'string') {
      throw new TypeError('LocalTrustAnchorStore: ownServerDid must be a non-empty string');
    }

    this._ownDid = options.ownServerDid;
    this._keystore = options.keystore ?? null;

    this._anchors.set(options.ownServerDid, {
      did: options.ownServerDid,
      source: 'local',
      addedAt: Math.floor(Date.now() / 1000),
      label: 'self',
    });

    if (options.initialTrustedServers && options.initialTrustedServers.length > 0) {
      for (const raw of options.initialTrustedServers) {
        const did = typeof raw === 'string' ? raw.trim() : '';
        if (!did) continue;
        if (this._anchors.has(did)) continue;
        this._anchors.set(did, {
          did,
          source: 'env',
          addedAt: Math.floor(Date.now() / 1000),
        });
      }
    }
  }

  /**
   * Add a trusted server DID.
   *
   * If the DID is already present (any source), the existing entry is overwritten
   * and NO 'server-discovered' event fires (idempotent update). If the DID is new,
   * the entry is added and 'server-discovered' fires.
   *
   * 'api' source additions are persisted to the keystore automatically.
   */
  async addTrustedServer(did: string, source: TrustAnchorSource, label?: string): Promise<void> {
    if (!did || typeof did !== 'string') {
      throw new TypeError(
        `TrustAnchorStore.addTrustedServer: did must be a non-empty string, got ${typeof did}`,
      );
    }

    const isNew = !this._anchors.has(did);
    const anchor: TrustAnchor = {
      did,
      source,
      addedAt: Math.floor(Date.now() / 1000),
      ...(label !== undefined && { label }),
    };
    this._anchors.set(did, anchor);

    await this._persist();

    if (isNew) {
      this.emit('server-discovered', anchor);
    }
  }

  /**
   * Remove a trusted server DID.
   *
   * Throws if the DID is the own server DID (source: 'local') — the server must
   * always trust itself. No-op if the DID was not in the set.
   * Emits 'server-removed' if a DID was successfully removed.
   */
  async removeTrustedServer(did: string): Promise<void> {
    // Checked against _ownDid (not source field) because a caller could add the own DID as 'api'.
    if (did === this._ownDid) {
      throw new Error(
        `TrustAnchorStore.removeTrustedServer: cannot remove own server DID '${did}'. ` +
          'The server must always trust itself.',
      );
    }

    if (this._anchors.has(did)) {
      this._anchors.delete(did);
      await this._persist();
      this.emit('server-removed', did);
    }
  }

  /**
   * Add a parent instance's issuer DID as a trust anchor.
   *
   * Validates DID format (must start with did:key: or did:dht:). Source 'parent' is NOT
   * persisted — _persist() filters to 'api' only so parent anchors don't outlive the session.
   */
  async addParentTrust(parentDid: string, label?: string): Promise<void> {
    if (!parentDid || typeof parentDid !== 'string') {
      throw new TypeError(
        `TrustAnchorStore.addParentTrust: parentDid must be a non-empty string, got ${typeof parentDid}`,
      );
    }

    // Only did:key and did:dht are supported — other methods introduce external resolution
    // dependencies that complicate offline-first credential verification.
    if (!parentDid.startsWith('did:key:') && !parentDid.startsWith('did:dht:')) {
      throw new TypeError(
        `TrustAnchorStore.addParentTrust: parentDid must be did:key: or did:dht:, got '${parentDid}'`,
      );
    }

    // Don't overwrite persistent anchors ('env', 'api', 'local') with ephemeral 'parent'.
    const existing = this._anchors.get(parentDid);
    if (
      existing &&
      (existing.source === 'env' || existing.source === 'api' || existing.source === 'local')
    ) {
      return;
    }

    await this.addTrustedServer(parentDid, 'parent', label ?? 'parent-instance');
  }

  /**
   * Check whether a DID is trusted. O(1) Map lookup.
   *
   * Called on every MCP request by AgentVerifier. Must not throw or block.
   */
  isTrusted(did: string): boolean {
    return this._anchors.has(did);
  }

  /**
   * Return all current anchors as an array snapshot.
   * Used by the MCP `discover` tool to expose the trust topology.
   */
  list(): TrustAnchor[] {
    return Array.from(this._anchors.values());
  }

  /**
   * Load persisted 'api' anchors from the keystore. Call once after construction.
   * Fails gracefully on missing or corrupted data — falls back to own-DID + env trust only.
   */
  async load(): Promise<void> {
    if (!this._keystore) return;
    const raw = await this._keystore.read(KEYSTORE_KEY);
    if (!raw) return;

    let persisted: TrustAnchor[];
    try {
      persisted = JSON.parse(raw) as TrustAnchor[];
    } catch {
      return; // Corrupted JSON — fail safe
    }

    for (const anchor of persisted) {
      if (typeof anchor.did !== 'string' || !anchor.did) continue;
      if (anchor.source !== 'api') continue;
      if (this._anchors.has(anchor.did)) continue; // Don't overwrite authoritative sources
      this._anchors.set(anchor.did, anchor);
    }
  }

  /**
   * Persist 'api' anchors to the keystore. Called automatically on mutations.
   * Exposed for explicit flushes (e.g., graceful shutdown). No-op without a keystore.
   */
  async persist(): Promise<void> {
    await this._persist();
  }

  private async _persist(): Promise<void> {
    if (!this._keystore) return;
    // Parent anchors MUST NOT be persisted — ephemerality ensures trust cannot outlive the credential.
    const toSave = Array.from(this._anchors.values()).filter((a) => a.source === 'api');
    await this._keystore.write(KEYSTORE_KEY, JSON.stringify(toSave));
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * createTrustAnchorStore — convenience factory for LocalTrustAnchorStore.
 *
 * Prefer this over `new LocalTrustAnchorStore()` in application code so the
 * instantiation site can be mocked in tests. Returns a LocalTrustAnchorStore
 * typed as TrustAnchorStore so callers depend on the interface, not the class.
 *
 * @example
 *   const store = createTrustAnchorStore({ ownServerDid: identity.did, keystore });
 *   await store.load();
 */
export function createTrustAnchorStore(options: {
  ownServerDid: string;
  keystore?: KeystoreBackend;
}): LocalTrustAnchorStore {
  return new LocalTrustAnchorStore(options);
}
