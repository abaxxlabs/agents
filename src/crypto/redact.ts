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

import { inspect } from 'node:util';

/** Redaction marker for 32-byte master key material. */
export const REDACTED_MASTER_KEY = '[REDACTED 32 bytes]' as const;

/** Redaction marker for opaque AgentSigner references. */
export const REDACTED_SIGNER = '[AgentSigner]' as const;

/**
 * Add redacted `toJSON()` and `[inspect.custom]()` to a plain object so that
 * `JSON.stringify`, `console.log`, and `util.inspect` never leak secret material.
 *
 * For classes, define `toJSON()` directly and add:
 *   `[inspect.custom]() { return this.toJSON(); }`
 * using the shared constants above for the redaction markers.
 *
 * @param target - the object to augment (mutated in place)
 * @param redactedView - returns the safe representation for serialisation
 * @returns the same object, for chaining
 *
 * @example
 * ```ts
 * const signer = withRedactedSerialization(
 *   { signJwt(p) { ... } },
 *   () => REDACTED_SIGNER,
 * );
 * JSON.stringify(signer); // '"[AgentSigner]"'
 * ```
 */
export function withRedactedSerialization<T extends object>(
  target: T,
  redactedView: () => unknown,
): T {
  Object.defineProperty(target, 'toJSON', {
    value: redactedView,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.defineProperty(target, inspect.custom, {
    value: redactedView,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return target;
}
