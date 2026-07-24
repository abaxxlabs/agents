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
 * Factories for identity-gated storage inputs. IdentityContext is structurally
 * forgeable, so callers must construct it only inside trusted verification paths.
 */

import type { AgentVerifyResult } from '#identity/index.js';
import type { IdentityContext } from './types.js';

/**
 * Creates an immutable context from a successful verification result.
 * @param result The successful AgentVerifier result.
 * @returns A frozen identity context.
 * @throws {TypeError} When subjectDid is empty.
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
 * Creates an administrative context where callerDid equals issuerDid.
 * Knowledge of a server DID is not authentication; call only from trusted code.
 * @param serverDid The server's own DID.
 */
export function createServerIdentityContext(serverDid: string): IdentityContext {
  if (!serverDid) {
    throw new TypeError('createServerIdentityContext: serverDid must be a non-empty string.');
  }

  return Object.freeze({
    callerDid: serverDid,
    issuerDid: serverDid,
    orgDomain: null,
    verifiedAt: Date.now(),
  });
}
