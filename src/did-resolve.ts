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

import { base58Decode } from './crypto/base58.js';
import { DidResolutionFailedError } from './errors.js';
import type { Did } from './domain-types.js';

/**
 * Resolve a `did:key` identifier to its raw Ed25519 public key bytes.
 *
 * @param did - A `did:key:z...` identifier.
 * @returns Raw 32-byte Ed25519 public key.
 * @throws {DidResolutionFailedError} if the DID is not a did:key or uses an unsupported key type.
 */
export function resolveDidKeyFallback(did: Did): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new DidResolutionFailedError(did, 'Not a did:key identifier');
  }

  const multibaseEncoded = did.slice('did:key:'.length);
  const decoded = base58Decode(multibaseEncoded.slice(1));

  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new DidResolutionFailedError(
      did,
      `Unsupported key type. Expected Ed25519 (0xed01), got 0x${decoded[0]?.toString(16)}${decoded[1]?.toString(16)}`,
    );
  }

  return decoded.slice(2);
}

export const resolveDidKey = resolveDidKeyFallback;
