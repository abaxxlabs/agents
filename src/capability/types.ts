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
 * Type definitions for CapabilityEngine. Distinct from ScopeEngine (SQL columns).
 *
 * CapabilityAction is a hybrid: closed template literal for known Abaxx namespaces
 * (autocomplete) plus `string & {}` for open extension — same pattern as CSS properties.
 * checkCapability() only checks the presented credential set; issuer-side policy is not re-enforced.
 * Fail-safe: unknown actions return allowed=false, never allowed=true.
 *
 * @see CAPABILITY-SPEC.md §2.1, §2.3
 */

// ─── CapabilityAction ────────────────────────────────────────────

/** Known, typed Abaxx action verbs. Adding new actions: minor version bump + CHANGELOG. */
type BuiltInAction =
  | `mcp:${'whoami' | 'sign' | 'discover' | 'challenge'}`
  | `agents:${'read' | 'write' | 'admin'}`
  | `identity:${'issue' | 'revoke' | 'verify' | 'bind'}`
  | `did:${'resolve' | 'publish' | 'rotate'}`
  | `vc:${'issue' | 'verify' | 'revoke' | 'present'}`
  | `scope:${'read' | 'write' | 'admin'}`
  | `agent:${'spawn' | 'terminate' | 'delegate'}`
  | `vault:${'read' | 'write' | 'share'}`
  | `audit:${'read' | 'export'}`
  // trust anchor management: list is free; add/remove are programmatic-only
  | `trust:${'add' | 'remove' | 'list'}`
  | `abaxx:${'exchange' | 'clear' | 'title' | 'kyc' | 'commodity' | 'settlement'}`;

/**
 * Action type for capability checks. Known namespaces are statically typed;
 * custom verbs accepted via `string & {}`. Must be canonical before comparison —
 * see normalizeAction() in engine.ts.
 */
export type CapabilityAction = BuiltInAction | (string & {});

// ─── Core Types ──────────────────────────────────────────────────

/**
 * A single granted permission.
 *
 * `action` is the operation being authorized (e.g., `jira:write`, `github:read`).
 * `scope` is an optional resource qualifier — when absent, the action is granted
 *   on any resource. When present, it is an exact-match qualifier today.
 *   Glob scopes are a future addition (e.g., `github:write` on `/main` but not
 *   on `/feature/*` — that distinction requires glob matching).
 * `constraints` are optional additional restrictions. Reserved for future use
 *   (e.g., `{ maxFileSize: 1024 }`, rate limits). Not evaluated today.
 */
export interface Capability {
  action: CapabilityAction;
  scope?: string;
  constraints?: Record<string, unknown>;
}

/** Ordered capability list from a VC credential subject. Hard limit: MAX_CAPABILITY_SET_SIZE. */
export type CapabilitySet = Capability[];

/**
 * The result of a checkCapability() call.
 *
 * `allowed` is true iff a matching capability was found.
 * `matchedCapability` is set only when allowed=true — the specific capability
 *   that granted access. Useful for audit logging and Cockpit provenance display.
 * `reason` is always present — a human-readable explanation naming the action,
 *   what was found in the credential set, and the resource.
 *
 * Reason format: "Action 'X' not permitted — credential grants ['Y'] on resource 'Z'"
 * Never: "Not allowed" — always name the denied action and what was found.
 */
export interface CapabilityCheckResult {
  allowed: boolean;
  matchedCapability?: Capability;
  reason: string;
}

// ─── Constants ───────────────────────────────────────────────────

/** Prevents O(n²) blowup in isSubsetOf() and runaway memory from malformed credentials. */
export const MAX_CAPABILITY_SET_SIZE = 500;

// ─── Error Types ─────────────────────────────────────────────────

/**
 * Thrown for malformed CapabilityAction values or unknown role names.
 * Programming error in the caller, not an authorization denial.
 * checkCapability() RETURNS { allowed: false } for denials; THROWS this for bad input.
 */
export class CapabilityParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CapabilityParseError';
  }
}

/** Thrown when a CapabilitySet exceeds MAX_CAPABILITY_SET_SIZE. */
export class CapabilitySetTooLargeError extends Error {
  constructor(actual: number) {
    super(
      `CapabilitySet exceeds maximum allowed size of ${MAX_CAPABILITY_SET_SIZE} (got ${actual}). ` +
        `If this is a legitimate credential, contact the issuer — normal credentials have 5-50 capabilities.`,
    );
    this.name = 'CapabilitySetTooLargeError';
  }
}
