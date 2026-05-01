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
 * IdentityContext — proof that a caller has been verified by AgentVerifier.
 *
 * Constructed only from AgentVerifyResult via createIdentityContext(). Cannot be
 * fabricated directly by application code. Passed to external-facing storage
 * operations (ContextStore) to enforce identity-gated access.
 *
 * Security decision: IdentityContext is a plain object (not a class with a
 * private constructor) because TypeScript's structural typing means a class
 * offers no real fabrication protection at runtime. Instead, the factory function
 * in identity-context.ts is the single construction point, and the TypeScript
 * module boundary provides compile-time discipline. Runtime code that needs to
 * verify an IdentityContext is genuine should check that verifiedAt is recent
 * (within the session's token TTL) and that callerDid is non-empty.
 *
 * Fields mirror AgentVerifyResult with renaming for clarity:
 *   - subjectDid → callerDid (the agent performing the storage operation)
 *   - issuerDid stays (the server that vouched for this agent)
 *   - orgDomain stays (org isolation enforcement)
 *   - verifiedAt is added (timestamp for staleness checks)
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
