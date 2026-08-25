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
 * MasterKey — branded Buffer for 32-byte symmetric master keys.
 *
 * The brand is a phantom type-only field — a MasterKey IS a Buffer at runtime.
 * Callers must produce one via `asMasterKey()`, which is the smart-constructor
 * choke point. Crypto primitives accept `MasterKey`, so passing a plain Buffer
 * is a compile error (reviewer-visible cast required to bypass).
 *
 * The brand does NOT prevent `console.log(masterKey)` or `JSON.stringify(...)` —
 * those accept `any`. Runtime redaction is handled by toJSON/util.inspect on the
 * holding instances.
 */

/**
 * Branded type for a validated 32-byte master key.
 * Phantom field — exists only in the type system. At runtime, a MasterKey is a plain Buffer.
 */
export type MasterKey = Buffer & { readonly __brand: 'MasterKey' };

/**
 * Smart constructor for MasterKey. Validates that the input Buffer is exactly
 * 32 bytes (the required size for AES-256 / HKDF-SHA256 keying material) and
 * returns it tagged as a MasterKey. Throws on invalid length.
 *
 * @param buf — a Buffer that the caller asserts contains key material.
 *   Caller is responsible for the source of trust (env var, KMS, vault).
 * @returns the same Buffer, retyped as MasterKey.
 * @throws Error if `buf.length !== 32`.
 *
 * @example
 * ```ts
 * import { asMasterKey } from '@abaxxlabs/agents';
 *
 * // Construct from a hex string at the consumer boundary.
 * const buf = Buffer.from(process.env.AGENTS_MASTER_KEY!, 'hex');
 * const masterKey = asMasterKey(buf);  // throws if not 32 bytes
 *
 * // Now `masterKey` is structurally a Buffer but nominally a MasterKey.
 * // It can be passed to any crypto primitive that accepts MasterKey, but
 * // the type system will reject it at sinks that take `unknown` or `any`
 * // unless the caller explicitly widens.
 * ```
 */
export function asMasterKey(buf: Buffer): MasterKey {
  if (buf.length !== 32) {
    throw new Error(`Master key must be exactly 32 bytes (got ${buf.length})`);
  }
  return buf as MasterKey;
}
