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
 * DID Alias Registry — alias-aware DID comparison for the identity migration grace period.
 *
 * Used ONLY for in-memory DID comparison (scope engine, vc-verifier). The `owner_did`
 * columns are updated atomically inside the migration transaction — they never use alias
 * expansion, preserving the "database enforces the boundary" invariant.
 *
 * Ordering invariant: register an alias BEFORE updating the in-memory agents Map so the
 * grace-period comparison is live before any query sees the new ownerDid.
 */

/**
 * A single DID alias record, mirroring the agent_did_aliases table.
 */
export interface DidAlias {
  oldDid: string;
  newDid: string;
  credentialHash: string;
  oidcSubject?: string;
  oidcIssuer?: string;
  migratedAt: Date;
  expiresAt: Date;
}

export class DidAliasRegistry {
  // Bidirectional maps for O(1) lookup in either direction.
  private oldToNew = new Map<string, DidAlias>();
  private newToOld = new Map<string, DidAlias>();
  private byCredentialHash = new Map<string, DidAlias>();

  /**
   * Load aliases from the database at startup. Call once during initialization.
   * Only loads non-expired aliases.
   */
  loadAliases(aliases: DidAlias[]): void {
    const now = new Date();
    for (const alias of aliases) {
      if (alias.expiresAt > now) {
        this.oldToNew.set(alias.oldDid, alias);
        this.newToOld.set(alias.newDid, alias);
        this.byCredentialHash.set(alias.credentialHash, alias);
      }
    }
  }

  /**
   * Register a new alias. Called during the migration transaction, BEFORE
   * updating the in-memory agents Map.
   */
  addAlias(alias: DidAlias): void {
    this.oldToNew.set(alias.oldDid, alias);
    this.newToOld.set(alias.newDid, alias);
    this.byCredentialHash.set(alias.credentialHash, alias);
  }

  /**
   * Check if a migration credential has already been processed (idempotency).
   */
  hasCredential(credentialHash: string): boolean {
    return this.byCredentialHash.has(credentialHash);
  }

  /**
   * Resolve a DID to its canonical (new) form, if an active alias exists.
   * Returns the input DID unchanged if no alias exists or the alias has expired.
   */
  resolveToNew(did: string): string {
    const alias = this.oldToNew.get(did);
    if (alias && alias.expiresAt > new Date()) {
      return alias.newDid;
    }
    return did;
  }

  /**
   * Get the old DID for a new DID, if an active alias exists.
   * Used for audit trail queries that need to include records under the old DID.
   */
  resolveToOld(did: string): string | undefined {
    const alias = this.newToOld.get(did);
    if (alias && alias.expiresAt > new Date()) {
      return alias.oldDid;
    }
    return undefined;
  }

  /**
   * Get all DIDs that should be treated as equivalent to the given DID.
   * Returns [did] if no alias exists, [oldDid, newDid] if an active alias exists.
   * Used for audit queries that need to match records under either DID.
   */
  allEquivalentDids(did: string): string[] {
    const fromOld = this.oldToNew.get(did);
    if (fromOld && fromOld.expiresAt > new Date()) {
      return [fromOld.oldDid, fromOld.newDid];
    }
    const fromNew = this.newToOld.get(did);
    if (fromNew && fromNew.expiresAt > new Date()) {
      return [fromNew.oldDid, fromNew.newDid];
    }
    return [did];
  }

  /**
   * Alias-aware DID comparison. Returns true if both DIDs refer to the same
   * identity, considering active (non-expired) aliases.
   *
   * Used in place of === for DID equality checks in:
   * - scope-engine.ts: owner check, delegation chain issuer, issuer consistency
   * - vc-verifier.ts: subject binding (if agent DID also migrates)
   *
   * Must be operational BEFORE the atomic migration updates the in-memory
   * agents Map (see ordering invariant in module docstring).
   */
  didsMatch(a: string, b: string): boolean {
    if (a === b) return true;

    const now = new Date();

    // Check if a is old and b is new (or vice versa)
    const aliasA = this.oldToNew.get(a);
    if (aliasA && aliasA.expiresAt > now && aliasA.newDid === b) return true;

    const aliasB = this.oldToNew.get(b);
    if (aliasB && aliasB.expiresAt > now && aliasB.newDid === a) return true;

    return false;
  }

  /**
   * Remove expired aliases. Call periodically or on startup.
   */
  evictExpired(): number {
    const now = new Date();
    let evicted = 0;
    for (const [oldDid, alias] of this.oldToNew) {
      if (alias.expiresAt <= now) {
        this.oldToNew.delete(oldDid);
        this.newToOld.delete(alias.newDid);
        this.byCredentialHash.delete(alias.credentialHash);
        evicted++;
      }
    }
    return evicted;
  }

  get size(): number {
    return this.oldToNew.size;
  }
}
