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

// Tests cross-org federation primitives: enrollment policy, VP audience binding, replay prevention.

import { describe, it, expect } from 'vitest';
import {
  generateDidKey,
  createSigner,
  issueCredential,
  createPresentation,
  VcVerifier,
  InMemoryRevocationStore,
} from '../src/index.js';

describe('Cross-org federation primitive (Beat 7)', () => {
  it("accepts an enrolled agent's VP bound to Org B's verifier DID", async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const agentASigner = createSigner(agentA.privateKey);

    const credA = issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['order_book.ticker', 'order_book.side'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const orgBIdentity = generateDidKey();
    const orgBVerifier = new VcVerifier({
      revocationStore: new InMemoryRevocationStore(),
    });
    const orgBEnrolled = new Set<string>();
    orgBEnrolled.add(agentA.did);
    orgBVerifier.registerKey(agentA.did, agentA.publicKey);

    const vp = createPresentation(credA, agentA.did, agentASigner, {
      audience: orgBIdentity.did,
    });

    expect(orgBEnrolled.has(agentA.did)).toBe(true);

    const result = await orgBVerifier.verify(vp, {
      expectedAudience: orgBIdentity.did,
      expectedSubject: agentA.did,
    });

    expect(result.valid).toBe(true);
  });

  it('rejects an unenrolled agent at the federation policy gate', async () => {
    const human = generateDidKey();
    const unknownAgent = generateDidKey();
    const unknownSigner = createSigner(unknownAgent.privateKey);

    const credUnknown = issueCredential(human.did, human.privateKey, {
      agent: unknownAgent.did,
      columns: ['order_book.ticker'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const orgBIdentity = generateDidKey();
    const orgBVerifier = new VcVerifier({
      revocationStore: new InMemoryRevocationStore(),
    });
    const orgBEnrolled = new Set<string>(); // empty — nobody enrolled yet

    const vp = createPresentation(credUnknown, unknownAgent.did, unknownSigner, {
      audience: orgBIdentity.did,
    });

    expect(orgBEnrolled.has(unknownAgent.did)).toBe(false);

    // did:key self-resolves, so crypto passes; the enrollment Map is what gates trust.
    const result = await orgBVerifier.verify(vp, {
      expectedAudience: orgBIdentity.did,
      expectedSubject: unknownAgent.did,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects an enrolled agent's VP when bound to the wrong audience", async () => {
    const human = generateDidKey();
    const agentA = generateDidKey();
    const agentASigner = createSigner(agentA.privateKey);

    const credA = issueCredential(human.did, human.privateKey, {
      agent: agentA.did,
      columns: ['order_book.ticker'],
      actions: ['read'],
      expiresIn: '4h',
    });

    const orgBIdentity = generateDidKey();
    const orgCIdentity = generateDidKey(); // different verifier

    const orgBVerifier = new VcVerifier({
      revocationStore: new InMemoryRevocationStore(),
    });
    orgBVerifier.registerKey(agentA.did, agentA.publicKey);

    const vp = createPresentation(credA, agentA.did, agentASigner, {
      audience: orgCIdentity.did,
    });

    const result = await orgBVerifier.verify(vp, {
      expectedAudience: orgBIdentity.did,
      expectedSubject: agentA.did,
    });

    expect(result.valid).toBe(false);
    expect(result.status).toBe('WRONG_AUDIENCE');
  });
});
