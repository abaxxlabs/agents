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
 * CapabilityEngine Canonical Test Vectors
 *
 * Single source of truth for CapabilityEngine correctness. All implementations
 * must pass every vector in this file.
 *
 * Vectors cover: allow/deny by action, scope matching, empty sets, subset
 * validation, role expansion, normalization, error cases, security invariants,
 * and boundary conditions.
 *
 * Imported by test/capability.test.ts as `testVectors`.
 */

import type { CapabilitySet } from '../../src/capability/types.js';
import { MAX_CAPABILITY_SET_SIZE } from '../../src/capability/types.js';

// ─── Type Definitions ────────────────────────────────────────────

/** A vector that tests checkCapability() */
export interface CheckVector {
  id: number;
  description: string;
  /** action is `unknown` to allow non-string input tests (ids 28, 29) */
  action: unknown;
  scope: string | undefined;
  capabilitySet: CapabilitySet;
  expected:
    | { allowed: true; matchedAction: string }
    | { allowed: false }
    | { throws: 'CapabilityParseError' | 'CapabilitySetTooLargeError' };
}

/** A vector that tests isSubsetOf() */
export interface SubsetVector {
  id: number;
  description: string;
  childSet: CapabilitySet;
  parentSet: CapabilitySet;
  expected: boolean | { throws: 'CapabilitySetTooLargeError' };
}

/** A vector that tests resolveRole() */
export interface RoleVector {
  id: number;
  description: string;
  role: string;
  roleMap: Record<string, CapabilitySet>;
  expected: CapabilitySet | { throws: 'CapabilityParseError' | 'CapabilitySetTooLargeError' };
}

// ─── checkCapability Vectors ─────────────────────────────────────

export const checkVectors: CheckVector[] = [
  // ── Core spec vectors (from §7 minimum required) ──────────────
  {
    id: 1,
    description: 'Allow — exact action+scope match',
    action: 'jira:read',
    scope: 'project/PROJ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
  {
    id: 2,
    description: 'Deny — action miss (jira:write not in set)',
    action: 'jira:write',
    scope: 'project/PROJ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: { allowed: false },
  },
  {
    id: 3,
    description: 'Deny — scope mismatch (action matches but scope does not)',
    action: 'file_write',
    scope: '/etc',
    capabilitySet: [{ action: 'file_write', scope: '/data/reports' }],
    expected: { allowed: false },
  },
  {
    id: 4,
    description: 'Allow — cap with no scope grants action on any resource',
    action: 'vc:verify',
    scope: '/anything',
    capabilitySet: [{ action: 'vc:verify' }],
    expected: { allowed: true, matchedAction: 'vc:verify' },
  },
  {
    id: 5,
    description: 'Deny — empty capability set',
    action: 'jira:read',
    scope: undefined,
    capabilitySet: [],
    expected: { allowed: false },
  },
  {
    id: 12,
    description: 'Throw CapabilityParseError — empty string action',
    action: '',
    scope: undefined,
    capabilitySet: [{ action: 'jira:read' }],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 13,
    description: 'Normalization — UPPERCASE action matches lowercase in credential',
    action: 'JIRA:READ',
    scope: 'project/PROJ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
  {
    id: 14,
    description: 'Allow — no scope requested, cap has no scope (any-resource grant)',
    action: 'mcp:whoami',
    scope: undefined,
    capabilitySet: [{ action: 'mcp:whoami' }],
    expected: { allowed: true, matchedAction: 'mcp:whoami' },
  },
  {
    id: 15,
    description: 'Deny — cap has scope but request has no scope',
    action: 'github:write',
    scope: undefined,
    capabilitySet: [{ action: 'github:write', scope: '/main' }],
    expected: { allowed: false },
  },
  {
    id: 16,
    description: 'Allow — first matching cap in set is returned',
    action: 'jira:read',
    scope: 'project/PROJ',
    capabilitySet: [
      { action: 'jira:write', scope: 'project/PROJ' },
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'jira:read', scope: 'project/OTHER' },
    ],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
  {
    id: 17,
    description: 'Throw CapabilityParseError — whitespace-only action',
    action: '   ',
    scope: undefined,
    capabilitySet: [],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 18,
    description: 'Allow — action with leading/trailing whitespace is normalized',
    action: '  jira:read  ',
    scope: 'project/PROJ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },

  // ── Boundary and error conditions ─────────────────────────────
  {
    id: 24,
    description: 'Throw CapabilitySetTooLargeError — set exceeds MAX_CAPABILITY_SET_SIZE',
    action: 'jira:read',
    scope: undefined,
    capabilitySet: Array.from({ length: MAX_CAPABILITY_SET_SIZE + 1 }, (_, i) => ({
      action: `ns:action${i}`,
    })),
    expected: { throws: 'CapabilitySetTooLargeError' },
  },
  {
    id: 25,
    description: 'Throw CapabilityParseError — non-ASCII character in action',
    action: 'jira:\u00e9read', // é is U+00E9, above 0x7E
    scope: undefined,
    capabilitySet: [],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 26,
    description: 'Throw CapabilityParseError — action exceeds 256 characters',
    action: 'a'.repeat(257),
    scope: undefined,
    capabilitySet: [],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 27,
    description: 'Allow — action at exactly 256 characters (boundary — must not throw)',
    action: 'a'.repeat(256),
    scope: undefined,
    capabilitySet: [{ action: 'a'.repeat(256) }],
    expected: { allowed: true, matchedAction: 'a'.repeat(256) },
  },
  {
    id: 28,
    description: 'Throw CapabilityParseError — non-string action: null',
    action: null,
    scope: undefined,
    capabilitySet: [],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 29,
    description: 'Throw CapabilityParseError — non-string action: number',
    action: 42,
    scope: undefined,
    capabilitySet: [],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 30,
    description: 'Allow — malformed cap in set is skipped; valid matching cap is still found',
    action: 'jira:read',
    scope: 'project/PROJ',
    capabilitySet: [
      { action: '' }, // malformed — skip
      { action: 'jira:read', scope: 'project/PROJ' }, // valid match
    ],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
  {
    id: 31,
    description: 'Throw CapabilityParseError — requested scope contains null byte',
    action: 'jira:read',
    scope: 'project/PROJ\0injected',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ\0injected' }],
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 32,
    description: 'Deny — scope is case-sensitive; Project/PROJ ≠ project/proj',
    action: 'jira:read',
    scope: 'project/proj', // lowercase
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }], // uppercase
    expected: { allowed: false },
  },
  {
    id: 33,
    description: 'Allow — constraints field is not evaluated',
    action: 'jira:read',
    scope: 'project/PROJ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ', constraints: { maxCalls: 10 } }],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
  {
    id: 34,
    description: 'Allow — scope with leading whitespace is trimmed and matches',
    action: 'jira:read',
    scope: '  project/PROJ  ',
    capabilitySet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: { allowed: true, matchedAction: 'jira:read' },
  },
];

// ─── isSubsetOf Vectors ──────────────────────────────────────────

export const subsetVectors: SubsetVector[] = [
  // ── Core spec vectors ─────────────────────────────────────────
  {
    id: 6,
    description: 'Valid subset — child is contained in parent',
    childSet: [{ action: 'jira:read' }],
    parentSet: [{ action: 'jira:read' }, { action: 'jira:write' }],
    expected: true,
  },
  {
    id: 7,
    description: 'Child exceeds parent — github:write not in parent',
    childSet: [{ action: 'github:write' }],
    parentSet: [{ action: 'github:read' }],
    expected: false,
  },
  {
    id: 8,
    description: 'Empty child is always a subset (vacuous truth)',
    childSet: [],
    parentSet: [{ action: 'anything' }],
    expected: true,
  },
  {
    id: 9,
    description: 'Empty child vs empty parent — still true',
    childSet: [],
    parentSet: [],
    expected: true,
  },
  {
    id: 19,
    description: 'Scope must also match — differing scopes are not equivalent',
    childSet: [{ action: 'github:write', scope: '/main' }],
    parentSet: [{ action: 'github:write', scope: '/feature' }],
    expected: false,
  },
  {
    id: 20,
    description: 'Multiple caps in child, all in parent',
    childSet: [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'jira:write', scope: 'project/PROJ' },
    ],
    parentSet: [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'jira:write', scope: 'project/PROJ' },
      { action: 'jira:admin', scope: 'project/PROJ' },
    ],
    expected: true,
  },
  {
    id: 21,
    description: 'Non-empty child vs empty parent — always false',
    childSet: [{ action: 'jira:read' }],
    parentSet: [],
    expected: false,
  },

  // ── Boundary and error conditions ─────────────────────────────
  {
    id: 35,
    description: 'Throw CapabilitySetTooLargeError — childSet exceeds MAX_CAPABILITY_SET_SIZE',
    childSet: Array.from({ length: MAX_CAPABILITY_SET_SIZE + 1 }, (_, i) => ({
      action: `ns:action${i}`,
    })),
    parentSet: [],
    expected: { throws: 'CapabilitySetTooLargeError' },
  },
  {
    id: 36,
    description: 'Throw CapabilitySetTooLargeError — parentSet exceeds MAX_CAPABILITY_SET_SIZE',
    childSet: [],
    parentSet: Array.from({ length: MAX_CAPABILITY_SET_SIZE + 1 }, (_, i) => ({
      action: `ns:action${i}`,
    })),
    expected: { throws: 'CapabilitySetTooLargeError' },
  },
  {
    id: 37,
    description: 'Normalization applied in subset check — UPPERCASE child matches lowercase parent',
    childSet: [{ action: 'JIRA:READ', scope: 'project/PROJ' }],
    parentSet: [{ action: 'jira:read', scope: 'project/PROJ' }],
    expected: true,
  },
  {
    id: 38,
    description: 'Malformed action in childSet → false (skip, not throw; cannot match parent)',
    childSet: [{ action: '' }],
    parentSet: [{ action: 'jira:read' }],
    expected: false,
  },
  {
    id: 39,
    description: 'Malformed action in parentSet → cap filtered out; child with that action → false',
    childSet: [{ action: 'jira:read' }],
    // The parent has a malformed cap that normalizes to the same key as the child.
    // Because capabilityKey returns null for malformed caps, the parent key set is empty.
    parentSet: [{ action: '' }],
    expected: false,
  },
];

// ─── resolveRole Vectors ─────────────────────────────────────────

export const roleVectors: RoleVector[] = [
  // ── Core spec vectors ─────────────────────────────────────────
  {
    id: 10,
    description: 'Known role expands to its capability set',
    role: 'viewer',
    roleMap: {
      viewer: [{ action: 'jira:read' }],
      editor: [{ action: 'jira:read' }, { action: 'jira:write' }],
    },
    expected: [{ action: 'jira:read' }],
  },
  {
    id: 11,
    description: 'Unknown role throws CapabilityParseError',
    role: 'superadmin',
    roleMap: {
      viewer: [{ action: 'jira:read' }],
    },
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 22,
    description: 'Empty roleMap throws CapabilityParseError',
    role: 'any-role',
    roleMap: {},
    expected: { throws: 'CapabilityParseError' },
  },
  {
    id: 23,
    description: 'Role with multiple capabilities returns full set',
    role: 'editor',
    roleMap: {
      editor: [
        { action: 'jira:read', scope: 'project/PROJ' },
        { action: 'jira:write', scope: 'project/PROJ' },
      ],
    },
    expected: [
      { action: 'jira:read', scope: 'project/PROJ' },
      { action: 'jira:write', scope: 'project/PROJ' },
    ],
  },

  // ── Boundary and error conditions ─────────────────────────────
  {
    id: 40,
    description:
      'Throw CapabilitySetTooLargeError — resolved role set exceeds MAX_CAPABILITY_SET_SIZE',
    role: 'mega-role',
    roleMap: {
      'mega-role': Array.from({ length: MAX_CAPABILITY_SET_SIZE + 1 }, (_, i) => ({
        action: `ns:action${i}`,
      })),
    },
    expected: { throws: 'CapabilitySetTooLargeError' },
  },
];

// ─── Combined export ─────────────────────────────────────────────

/**
 * All canonical test vectors. Imported by test/capability.test.ts.
 * All implementations must pass every vector in this collection.
 */
export const testVectors = {
  check: checkVectors,
  subset: subsetVectors,
  role: roleVectors,
};
