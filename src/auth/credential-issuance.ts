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

import { randomUUID } from 'node:crypto';
import type { IssueCredentialOptions, AgentSigner } from '../types.js';
import { createJwt } from '../vc-verifier.js';
import { validateScope, validateExpiry } from './delegation-policy.js';
import { parseDuration } from '../config.js';
import {
  assertScopeFitsInCeiling,
  type ScopeCeiling,
  type IssuanceContext,
} from './ceiling.js';
import type { IdSdkInstance } from '../id-sdk-types.js';


/** Convert expiresIn (string duration or integer seconds) to milliseconds. */
function expiresInToMs(expiresIn: string | number): number {
  if (typeof expiresIn === 'number') {
    if (!Number.isFinite(expiresIn) || expiresIn <= 0 || !Number.isInteger(expiresIn)) {
      throw new Error(`Invalid expiresIn: ${expiresIn}. Must be a positive integer (seconds).`);
    }
    return expiresIn * 1_000;
  }
  const ms = parseDuration(expiresIn);
  if (ms <= 0) {
    throw new Error(`Invalid expiresIn: ${expiresIn}. Duration must be positive.`);
  }
  return ms;
}

/**
 * Issue a scoped Verifiable Credential via the platform identity SDK.
 *
 * @param sdk - platform identity handle
 * @param humanDid - the human's DID that will be the credential issuer
 * @param options - scope, actions, TTL, and target agent
 */
export async function issueCredentialWithSdk(
  sdk: IdSdkInstance,
  humanDid: string,
  options: IssueCredentialOptions,
): Promise<string> {
  const expiresInMs = expiresInToMs(options.expiresIn);
  const expirationDate = new Date(Date.now() + expiresInMs).toISOString();

  const credentialData = {
    id: options.agent,
    scope: {
      columns: options.columns,
      actions: options.actions,
    },
    owner: humanDid,
    ...(options.metadata ?? {}),
  };

  const vc = await sdk.vc.createCredential(
    humanDid,
    options.agent,
    credentialData,
    'AgentScopeCredential',
  );

  const signerOptions = await sdk.vc.getSignerOptions(humanDid);
  return sdk.vc.signCredential(vc, { ...signerOptions, expirationDate });
}

/**
 * Issue a scoped Verifiable Credential using a local Ed25519 private key.
 *
 * @param humanDid - the human's DID
 * @param humanPrivateKey - raw 32-byte Ed25519 private key
 * @param options - scope, actions, TTL, and target agent
 */
export function issueCredential(
  humanDid: string,
  humanPrivateKey: Uint8Array,
  options: IssueCredentialOptions,
): string {
  const now = Math.floor(Date.now() / 1000);
  const expiresInMs = expiresInToMs(options.expiresIn);
  const exp = now + Math.floor(expiresInMs / 1000);

  const payload = {
    iss: humanDid,
    sub: options.agent,
    jti: randomUUID(),
    iat: now,
    exp,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'AgentScopeCredential'],
      credentialSubject: {
        id: options.agent,
        scope: {
          columns: options.columns,
          actions: options.actions,
        },
        owner: humanDid,
        ...(options.metadata ?? {}),
      },
    },
  };

  return createJwt(payload, humanPrivateKey);
}

/**
 * Issue a delegated credential from one agent to another.
 *
 * @param delegatorDid - the supervisor agent's DID
 * @param delegatorSigner - the supervisor's opaque signer
 * @param sourceCredentialJwt - the supervisor's own credential JWT (for the delegation chain)
 * @param sourceCredentialJti - JTI of the source credential for audit trail
 * @param sourceScope - the supervisor's authorized scope
 * @param options - target agent, requested scope subset, TTL, and metadata
 */
export function issueDelegatedCredential(
  delegatorDid: string,
  delegatorSigner: AgentSigner,
  sourceCredentialJwt: string,
  sourceCredentialJti: string,
  sourceScope: { columns: string[]; actions: string[] },
  options: {
    targetAgent: string;
    columns: string[];
    actions: 'read'[];
    expiresIn: string | number;
    maxExpSeconds?: number;
    metadata?: Record<string, unknown>;
  },
): string {
  validateScope(sourceScope, { columns: options.columns, actions: options.actions });

  const now = Math.floor(Date.now() / 1000);
  const requestedMs = expiresInToMs(options.expiresIn);
  const requestedExp = now + Math.floor(requestedMs / 1000);
  const exp = validateExpiry(requestedExp, options.maxExpSeconds);

  const payload = {
    iss: delegatorDid,
    sub: options.targetAgent,
    jti: randomUUID(),
    iat: now,
    exp,
    delegationChain: [sourceCredentialJwt],
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DelegatedAgentScopeCredential'],
      credentialSubject: {
        id: options.targetAgent,
        scope: {
          columns: options.columns,
          actions: options.actions,
        },
        grantedBy: delegatorDid,
        grantedTo: options.targetAgent,
        delegatedGrantId: sourceCredentialJti,
        delegated: false,
        ...(options.metadata ?? {}),
      },
    },
  };

  return delegatorSigner.signJwt(payload);
}

/**
 * Issue an agent credential through an AbaxxOne parent instance.
 *
 * @param provider - the AbaxxOne OIDC provider instance
 * @param accessToken - the human's OAuth access token
 * @param agentDid - the agent's DID to bind the credential to
 * @param options - requested scope and TTL
 * @param opts - optional ceiling enforcement params
 * @returns the signed JWT string from the parent instance
 */
export async function issueCredentialFromParent(
  provider: {
    requestAgentCredential: (
      accessToken: string,
      agentDid: string,
      options: { columns: string[]; actions: string[]; expiresIn: string | number },
    ) => Promise<{ jwt: string; issuerDid: string }>;
  },
  accessToken: string,
  agentDid: string,
  options: { columns: string[]; actions: string[]; expiresIn: string | number },
  opts?: { ceiling?: ScopeCeiling; context?: IssuanceContext },
): Promise<{ jwt: string; issuerDid: string }> {
  if (opts?.ceiling) {
    assertScopeFitsInCeiling(
      { columns: options.columns, actions: options.actions },
      opts.ceiling,
      opts.context,
    );
  }
  return provider.requestAgentCredential(accessToken, agentDid, options);
}
