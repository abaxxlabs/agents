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
 * CapabilityEngine — action-based authorization for connected agents.
 * Distinct from ScopeEngine (SQL columns) — different layer, different primitive.
 *
 * Normalization: actions are fully normalized (lowercase, ASCII, max 256 chars).
 * Scopes are edge-normalized (trim, no null bytes, max 1024 chars) but case-preserved —
 * lowercasing would break resource identifiers like "project/PROJ" or git branches.
 *
 * Malformed caps in stored sets are skipped (not thrown) — a single bad issuer entry
 * must not poison the full credential check. Malformed REQUESTED actions throw (caller bug).
 * Denial reasons name the denied action only — not the full granted set (enumeration oracle).
 *
 * @see docs/specs/CAPABILITY-SPEC.md
 */

import {
  type Capability,
  type CapabilityAction,
  type CapabilityCheckResult,
  type CapabilitySet,
  CapabilityParseError,
  CapabilitySetTooLargeError,
  MAX_CAPABILITY_SET_SIZE,
} from './types.js';

// ─── Normalization ───────────────────────────────────────────────

/**
 * Normalize a CapabilityAction: trim, lowercase, ASCII printable (0x20–0x7E), max 256 chars.
 * charCodeAt (not codePointAt) is intentional — non-BMP chars produce surrogate pairs
 * in 0xD800–0xDFFF, both > 0x7E and correctly rejected.
 *
 * @throws {CapabilityParseError} for empty, non-string, non-ASCII, or over-length input
 */
function normalizeAction(action: unknown): string {
  if (typeof action !== 'string') {
    throw new CapabilityParseError(`CapabilityAction must be a string, got ${typeof action}`);
  }

  const trimmed = action.trim();

  if (trimmed.length === 0) {
    throw new CapabilityParseError('CapabilityAction must not be empty or whitespace-only');
  }

  if (trimmed.length > 256) {
    throw new CapabilityParseError(
      `CapabilityAction exceeds maximum length of 256 characters (got ${trimmed.length})`,
    );
  }

  for (let i = 0; i < trimmed.length; i++) {
    const cp = trimmed.charCodeAt(i);
    if (cp < 0x20 || cp > 0x7e) {
      throw new CapabilityParseError(
        `CapabilityAction contains non-ASCII or control character at position ${i}: U+${cp.toString(16).padStart(4, '0')}`,
      );
    }
  }

  return trimmed.toLowerCase();
}

/**
 * Normalize a scope: trim, max 1024 chars, no null bytes.
 * Not lowercased — case is meaningful in resource identifiers (Jira keys, git branches, paths).
 * No null bytes — the capabilityKey separator is \0; null bytes enable key collision attacks.
 */
function normalizeScope(scope: string): string {
  const trimmed = scope.trim();

  if (trimmed.length > 1024) {
    throw new CapabilityParseError(
      `Scope exceeds maximum length of 1024 characters (got ${trimmed.length})`,
    );
  }

  if (trimmed.includes('\0')) {
    throw new CapabilityParseError(
      'Scope must not contain null bytes (would corrupt capability key)',
    );
  }

  return trimmed;
}

/**
 * Build a lookup key `{normalizedAction}\0{normalizedScope}` for O(n) set membership.
 * Null-byte separator is safe — normalizeAction rejects \0, normalizeScope explicitly rejects \0.
 * Returns null for malformed caps (callers treat null as non-matching).
 */
function capabilityKey(cap: Capability): string | null {
  try {
    const action = normalizeAction(cap.action);
    const scope = cap.scope !== undefined ? normalizeScope(cap.scope) : '';
    return `${action}\0${scope}`;
  } catch {
    return null; // malformed cap — non-matching by definition
  }
}

// ─── CapabilityEngine ────────────────────────────────────────────

/**
 * Stateless engine for capability checks, delegation validation, and role expansion.
 * Instantiate once and reuse. For functional style, use createCapabilityEngine().
 *
 * @see docs/specs/CAPABILITY-SPEC.md
 * @throws {CapabilityParseError} on malformed requested action strings or unknown roles
 * @throws {CapabilitySetTooLargeError} when a set exceeds MAX_CAPABILITY_SET_SIZE
 */
export class CapabilityEngine {
  /**
   * Determine whether action+scope is permitted by the presented capability set.
   *
   * Matching semantics: exact match after normalization. A capability with no
   * scope grants the action on any resource. A capability with a scope grants
   * the action only on that exact resource string (after scope normalization).
   *
   * Malformed caps in capabilitySet are skipped, not thrown. CapabilitySets arrive
   * from VC JWT payloads; a single bad issuer entry must not poison the entire check.
   *
   * Returns { allowed: false } for authorization denials — does NOT throw.
   * Throws CapabilityParseError for malformed REQUESTED action (caller bug).
   * This asymmetry is intentional: denials are expected outcomes; parse errors on the
   * requested action indicate a bug in the calling code.
   *
   * Denial reasons identify the denied action and resource only — they do NOT enumerate
   * the full granted capability set. Doing so would create an enumeration oracle.
   *
   * @param action  - The operation being requested. Will be normalized.
   * @param scope   - The resource being accessed, or undefined for any resource.
   * @param capabilitySet - The capabilities from the agent's VC credential subject.
   * @returns CapabilityCheckResult with allowed, optional matchedCapability, and reason.
   *
   * @throws {CapabilityParseError} if the requested action is malformed
   * @throws {CapabilitySetTooLargeError} if capabilitySet.length > MAX_CAPABILITY_SET_SIZE
   *
   * @see docs/specs/CAPABILITY-SPEC.md §3.1
   */
  checkCapability(
    action: CapabilityAction,
    scope: string | undefined,
    capabilitySet: CapabilitySet,
  ): CapabilityCheckResult {
    const normalizedAction = normalizeAction(action);
    const normalizedScope = scope !== undefined ? normalizeScope(scope) : undefined;

    if (capabilitySet.length > MAX_CAPABILITY_SET_SIZE) {
      throw new CapabilitySetTooLargeError(capabilitySet.length);
    }

    if (capabilitySet.length === 0) {
      return {
        allowed: false,
        reason: `Action '${normalizedAction}' not permitted — capability set is empty`,
      };
    }

    for (const cap of capabilitySet) {
      let capAction: string;
      try {
        capAction = normalizeAction(cap.action);
      } catch {
        continue; // malformed cap in VC — skip
      }

      if (capAction !== normalizedAction) {
        continue;
      }

      let capScope: string | undefined;
      if (cap.scope !== undefined) {
        try {
          capScope = normalizeScope(cap.scope);
        } catch {
          continue; // malformed scope in cap — skip
        }
      }

      if (capScope === undefined || capScope === normalizedScope) {
        const resourceLabel = normalizedScope ? `'${normalizedScope}'` : 'any resource';
        return {
          allowed: true,
          matchedCapability: cap,
          reason: `Action '${normalizedAction}' permitted on resource ${resourceLabel}`,
        };
      }
    }

    const resourceLabel = normalizedScope ? `'${normalizedScope}'` : 'any resource';
    return {
      allowed: false,
      reason: `Action '${normalizedAction}' not permitted on ${resourceLabel}`,
    };
  }

  /**
   * Determine whether childSet is entirely contained within parentSet.
   *
   * Used for delegation validation: a delegator cannot grant a delegatee capabilities
   * the delegator does not hold. isSubsetOf(delegateeSet, delegatorSet) must return
   * true before issuing a delegated credential.
   *
   * Conservative: any capability in childSet that is not an exact match in parentSet
   * returns false. Malformed caps in either set are treated as non-matching (not thrown)
   * — a malformed parent entry can never be matched, so it has no effect on the result;
   * a malformed child entry cannot exist in parent, so it causes a false return.
   *
   * O(n) implementation: builds a Set from parentSet, iterates childSet once.
   *
   * @param childSet  - The capability set being delegated to the child.
   * @param parentSet - The capability set held by the delegating parent.
   * @returns true iff every valid capability in childSet is in parentSet.
   *
   * @throws {CapabilitySetTooLargeError} if either set exceeds MAX_CAPABILITY_SET_SIZE
   *
   * @see docs/specs/CAPABILITY-SPEC.md §3.2
   */
  isSubsetOf(childSet: CapabilitySet, parentSet: CapabilitySet): boolean {
    if (childSet.length > MAX_CAPABILITY_SET_SIZE) {
      throw new CapabilitySetTooLargeError(childSet.length);
    }
    if (parentSet.length > MAX_CAPABILITY_SET_SIZE) {
      throw new CapabilitySetTooLargeError(parentSet.length);
    }

    // Empty child is always a subset of anything (vacuous truth)
    if (childSet.length === 0) {
      return true;
    }

    // O(1) lookup from parent — null keys from malformed caps are filtered out.
    const parentKeys = new Set<string>(
      parentSet.map(capabilityKey).filter((k): k is string => k !== null),
    );

    for (const child of childSet) {
      const key = capabilityKey(child);
      if (key === null || !parentKeys.has(key)) { // null = malformed → not in parent → not a subset
        return false;
      }
    }

    return true;
  }

  /**
   * Expand a named role to its capability set.
   *
   * Roles are defined in the VC credential subject by the issuer. This operation
   * is a simple map lookup — no recursive expansion, no role-of-roles.
   *
   * Error messages do not enumerate available role names — role inventories are
   * issuer-internal and should not be discoverable via error probing.
   *
   * @param role    - The role name to expand (e.g., "viewer", "editor").
   * @param roleMap - A map from role name to CapabilitySet, from the credential subject.
   * @returns The CapabilitySet for the given role.
   *
   * @throws {CapabilityParseError} if role is not found in roleMap
   * @throws {CapabilitySetTooLargeError} if the resolved set exceeds MAX_CAPABILITY_SET_SIZE
   *
   * @see docs/specs/CAPABILITY-SPEC.md §3.3
   */
  resolveRole(role: string, roleMap: Record<string, CapabilitySet>): CapabilitySet {
    if (!(role in roleMap)) {
      // Don't enumerate role names — role inventories are issuer-internal (probing oracle).
      throw new CapabilityParseError(`Unknown role: '${role}'`);
    }

    const resolved = roleMap[role];

    if (resolved.length > MAX_CAPABILITY_SET_SIZE) {
      throw new CapabilitySetTooLargeError(resolved.length);
    }

    return resolved;
  }
}

// ─── Factory ─────────────────────────────────────────────────────

/** Factory alias for `new CapabilityEngine()`. */
export function createCapabilityEngine(): CapabilityEngine {
  return new CapabilityEngine();
}
