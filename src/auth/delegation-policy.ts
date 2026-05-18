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
 *
 * @param parentScope - the delegator's authorized scope
 * @param requestedScope - the scope requested for the delegate
 * @throws Error if any requested column or action is not in the parent's scope
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
 *
 * @param requestedExpSeconds - requested expiry as epoch seconds
 * @param parentMaxExpSeconds - parent credential's maximum expiry as epoch seconds
 * @returns the effective expiry, clamped to parentMaxExpSeconds if it would exceed it
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
 * Validate that the delegation chain depth does not exceed the maximum allowed.
 *
 * @param chainLength - current chain length (number of credentials in the chain)
 * @param maxDepth - maximum allowed chain depth
 * @throws Error if chain depth is exceeded
 */
export function validateChain(chainLength: number, maxDepth: number): void {
  if (chainLength >= maxDepth) {
    throw new Error(
      `Delegation error: chain depth ${chainLength} exceeds maximum ${maxDepth}.`,
    );
  }
}
