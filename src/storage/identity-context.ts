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
 * Factory for IdentityContext — the proof-of-verification token for identity-gated
 * storage operations. Only constructable from an AgentVerifier.verify() result.
 * Untrusted MCP callers never receive IdentityContext; they present bearer tokens
 * that the server verifies before constructing one on their behalf.
 */

import type { AgentVerifyResult } from '#identity/index.js';
import type { IdentityContext } from './types.js';

/**
 * Create an IdentityContext from a successful AgentVerifier.verify() result.
 *
 * This is the only sanctioned way to construct an IdentityContext. The resulting
 * object is frozen (Object.freeze) to prevent post-construction mutation.
 *
 * @param result — the AgentVerifyResult from a successful verify() call.
 * @returns a frozen IdentityContext ready for use with ContextStore operations.
 *
 * @throws {TypeError} if result.subjectDid is empty (programming error — should
 *   never happen if AgentVerifier is working correctly, but defense in depth).
 *
 * @example
 *   const verifyResult = await agentVerifier.verify({ bindingJwt, agentDid });
 *   const identity = createIdentityContext(verifyResult);
 *   const entry = await backend.context.get('context-graph', 'decision:abc', identity);
 */
export function createIdentityContext(result: AgentVerifyResult): IdentityContext {
  if (!result.subjectDid) {
    throw new TypeError(
      'createIdentityContext: subjectDid must be a non-empty string. ' +
        'This indicates AgentVerifier returned an invalid result.',
    );
  }

  return Object.freeze({
    callerDid: result.subjectDid,
    issuerDid: result.issuerDid,
    orgDomain: result.orgDomain,
    verifiedAt: Date.now(),
  });
}

/**
 * Create a server IdentityContext for admin/internal operations.
 *
 * When the server itself needs to perform context store operations (backup,
 * export, context injection into child sessions), it constructs an IdentityContext
 * where callerDid === issuerDid. This triggers the "server identity bypass" in
 * ContextStore implementations, granting read/write access to all entries.
 *
 * Security decision: this function requires the server's own DID — it cannot
 * be called without access to the server's identity, which is only available
 * in the trusted zone (cockpit process). Untrusted child processes never have
 * the server DID; they present bearer tokens that resolve to their own agent DID.
 *
 * @param serverDid — the server's own DID (from ServerIdentity.did).
 *
 * @example
 *   const serverIdentity = createServerIdentityContext(serverIdentity.did);
 *   const allEntries = await backend.context.list('context-graph', serverIdentity);
 */
export function createServerIdentityContext(serverDid: string): IdentityContext {
  if (!serverDid) {
    throw new TypeError('createServerIdentityContext: serverDid must be a non-empty string.');
  }

  return Object.freeze({
    callerDid: serverDid,
    issuerDid: serverDid, // callerDid === issuerDid triggers server bypass
    orgDomain: null,
    verifiedAt: Date.now(),
  });
}
