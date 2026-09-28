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
 * Validate that requested columns and actions are subsets of the parent's scope.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function validateScope(
  parentScope: { columns: string[]; actions: string[] },
  requestedScope: { columns: string[]; actions: string[] },
): void {
  const parentColumns = new Set(parentScope.columns);
  for (const col of requestedScope.columns) {
    if (!parentColumns.has(col)) {
      throw new Error(
        `Delegation error: column '${col}' is not in the delegator's scope. ` +
          `Delegator has: [${parentScope.columns.join(', ')}]`,
      );
    }
  }
  const parentActions = new Set(parentScope.actions);
  for (const action of requestedScope.actions) {
    if (!parentActions.has(action)) {
      throw new Error(`Delegation error: action '${action}' is not in the delegator's scope.`);
    }
  }
}

/**
 * Clamp the requested expiry to the parent's maximum.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function validateExpiry(requestedExpSeconds: number, parentMaxExpSeconds?: number): number {
  if (parentMaxExpSeconds !== undefined) {
    return Math.min(requestedExpSeconds, parentMaxExpSeconds);
  }
  return requestedExpSeconds;
}

/**
 * Validate that the delegation chain depth does not exceed maxDepth.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function validateChain(chainLength: number, maxDepth: number): void {
  if (chainLength >= maxDepth) {
    throw new Error(`Delegation error: chain depth ${chainLength} exceeds maximum ${maxDepth}.`);
  }
}

/**
 * Library default — used when a credential lacks an embedded ceiling.
 * Current behavior: because re-delegation is intentionally blocked by design,
 * every ceiling above 2 is currently equivalent to 2 in practice — only one
 * delegation hop is possible. This default is still forward-compatible
 * infrastructure for a future multi-hop delegation model.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export const DEFAULT_MAX_DELEGATION_DEPTH = 2;

/** `type` value identifying the delegation ceiling inside `vc.termsOfUse`. */
export const DELEGATION_POLICY_TYPE = 'DelegationPolicy';

/** `type` value identifying the ancestor chain inside `vc.evidence`. */
export const DELEGATION_CHAIN_TYPE = 'DelegationChain';

/**
 * Credential envelope the delegation readers understand.
 *
 * The delegation ceiling and the ancestor chain live inside the `vc` object,
 * where they are part of the credential rather than of the token carrying it.
 * Both are also accepted at the JWT top level, which is where they used to sit,
 * so credentials issued before the move keep verifying.
 * @internal Not part of the public API.
 */
export interface DelegationClaimSource {
  maxDepth?: unknown;
  delegationChain?: unknown;
  vc?: {
    termsOfUse?: unknown;
    evidence?: unknown;
    [key: string]: unknown;
  };
}

/** True when a VC sub-object's `type` (string or array) contains `expected`. */
function hasType(entry: unknown, expected: string): entry is Record<string, unknown> {
  if (typeof entry !== 'object' || entry === null) return false;
  const t = (entry as { type?: unknown }).type;
  return Array.isArray(t) ? t.includes(expected) : t === expected;
}

/** First entry of a VC property (array or single object) carrying `expected` in its `type`. */
function findTyped(property: unknown, expected: string): Record<string, unknown> | undefined {
  const entries = Array.isArray(property) ? property : [property];
  for (const entry of entries) {
    if (hasType(entry, expected)) return entry;
  }
  return undefined;
}

function asPositiveInt(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : undefined;
}

/**
 * Read the delegation ceiling from a JWT payload; undefined if absent or malformed.
 *
 * Reads `vc.termsOfUse` first and falls back to the legacy top-level `maxDepth`
 * claim, so credentials issued before the claim moved keep verifying. The
 * fallback is transitional and is removed once no unexpired credential carries
 * the legacy shape.
 *
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function extractMaxDepth(payload: DelegationClaimSource): number | undefined {
  const terms = findTyped(payload.vc?.termsOfUse, DELEGATION_POLICY_TYPE);
  const fromTerms = asPositiveInt(terms?.['maxDepth']);
  if (fromTerms !== undefined) return fromTerms;
  return asPositiveInt(payload.maxDepth);
}

/**
 * Read the ancestor chain from a JWT payload. Returns the array as found —
 * including an empty one, which callers treat as malformed — or undefined when
 * the credential carries no chain at all.
 *
 * Reads `vc.evidence` first and falls back to the legacy top-level
 * `delegationChain` claim, on the same transitional basis as `extractMaxDepth`.
 *
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function extractDelegationChain(payload: DelegationClaimSource): unknown[] | undefined {
  const evidence = findTyped(payload.vc?.evidence, DELEGATION_CHAIN_TYPE);
  const credentials = evidence?.['credentials'];
  if (Array.isArray(credentials)) return credentials;
  return Array.isArray(payload.delegationChain) ? payload.delegationChain : undefined;
}

/**
 * Smallest embedded ceiling across source + ancestors; library default for missing values.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function resolveInheritedMaxDepth(
  sourcePayload: DelegationClaimSource,
  chainPayloads: ReadonlyArray<DelegationClaimSource>,
): number {
  const candidates = [sourcePayload, ...chainPayloads].map(
    (p) => extractMaxDepth(p) ?? DEFAULT_MAX_DELEGATION_DEPTH,
  );
  return Math.min(...candidates);
}
