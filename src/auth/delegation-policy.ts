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
export function validateExpiry(
  requestedExpSeconds: number,
  parentMaxExpSeconds?: number,
): number {
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
    throw new Error(
      `Delegation error: chain depth ${chainLength} exceeds maximum ${maxDepth}.`,
    );
  }
}

/**
 * Library default — used when a credential lacks an embedded ceiling.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export const DEFAULT_MAX_DELEGATION_DEPTH = 2;

/**
 * Read top-level maxDepth from a JWT payload; undefined if absent or malformed.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function extractMaxDepth(payload: { maxDepth?: unknown }): number | undefined {
  const v = payload.maxDepth;
  return typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : undefined;
}

/**
 * Smallest embedded ceiling across source + ancestors; library default for missing values.
 * @internal Not part of the public API. Consumed by the credential-issuance orchestrator.
 */
export function resolveInheritedMaxDepth(
  sourcePayload: { maxDepth?: unknown },
  chainPayloads: ReadonlyArray<{ maxDepth?: unknown }>,
): number {
  const candidates = [sourcePayload, ...chainPayloads].map(
    (p) => extractMaxDepth(p) ?? DEFAULT_MAX_DELEGATION_DEPTH,
  );
  return Math.min(...candidates);
}
