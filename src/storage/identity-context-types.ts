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
 * Verified caller data passed to identity-gated storage operations. The plain
 * object is structurally forgeable, so trust must come from the verification
 * path that creates it rather than from this TypeScript shape.
 */
export interface IdentityContext {
  /** DID of the verified agent performing the storage operation. */
  readonly callerDid: string;
  /** DID of the server that issued the binding credential. */
  readonly issuerDid: string;
  /** Org domain from the credential (null for consumer accounts). */
  readonly orgDomain: string | null;
  /** Unix timestamp (ms) when AgentVerifier.verify() succeeded. */
  readonly verifiedAt: number;
}
