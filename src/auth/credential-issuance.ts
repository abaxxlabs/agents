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
import type { IssueCredentialOptions } from '#types/credential.js';
import type { AgentSigner } from '#types/auth.js';
import { createJwt } from '#crypto/jwt.js';
import { decodeJwt } from '#crypto/jwt.js';
import {
  validateScope,
  validateExpiry,
  validateChain,
  resolveInheritedMaxDepth,
  DEFAULT_MAX_DELEGATION_DEPTH,
} from './delegation-policy.js';
import { expiresInToMs, assertExpiresInBound } from '#config.js';
import {
  assertScopeFitsInCeiling,
  type ScopeCeiling,
  type IssuanceContext,
} from './ceiling.js';
import type { IdSdkInstance } from '#types/id-sdk.js';

/** Match short-form and JSON-LD namespaced URI forms (`#`/`/` suffix) without full context resolution. */
export function isDelegatedScopeCredentialType(types: readonly unknown[]): boolean {
  return types.some(
    (t): t is string =>
      typeof t === 'string' &&
      (t === 'DelegatedAgentScopeCredential' ||
        t.endsWith('#DelegatedAgentScopeCredential') ||
        t.endsWith('/DelegatedAgentScopeCredential')),
  );
}

/** Issue a scoped Verifiable Credential via the platform identity SDK. */
export async function issueCredentialWithSdk(
  sdk: IdSdkInstance,
  humanDid: string,
  options: IssueCredentialOptions,
): Promise<string> {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH;
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new Error(
      `issueCredentialWithSdk: maxDepth must be a positive integer, received ${String(options.maxDepth)}.`,
    );
  }
  const expiresInMs = expiresInToMs(options.expiresIn);
  const expirationDate = new Date(Date.now() + expiresInMs).toISOString();

  const credentialData = {
    ...(options.metadata ?? {}),
    id: options.agent,
    scope: {
      columns: options.columns,
      actions: options.actions,
    },
    owner: humanDid,
    maxDepth,
  };

  const vc = await sdk.vc.createCredential(
    humanDid,
    options.agent,
    credentialData,
    'AgentScopeCredential',
  );

  const signerOptions = await sdk.vc.getSignerOptions(humanDid, options.agent);
  return sdk.vc.signCredential(vc, { ...signerOptions, expirationDate });
}

/**
 * Issue a scoped Verifiable Credential using a local Ed25519 private key.
 *
 * @throws {Error} If `options.maxDepth` is supplied but is not a positive
 *   integer (>= 1) — message: `maxDepth must be a positive integer`.
 */
export async function issueCredential(
  humanDid: string,
  humanPrivateKey: Uint8Array,
  options: IssueCredentialOptions,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expiresInMs = expiresInToMs(options.expiresIn);
  const exp = now + Math.floor(expiresInMs / 1000);
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH;
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new Error(
      `issueCredential: maxDepth must be a positive integer, received ${String(options.maxDepth)}.`,
    );
  }

  const payload = {
    iss: humanDid,
    sub: options.agent,
    jti: randomUUID(),
    iat: now,
    exp,
    maxDepth,
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

  return await createJwt(payload, humanPrivateKey);
}

/** Issue a delegated credential from one agent to another. Validates scope subset and chain depth. */
export async function issueDelegatedCredential(
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
): Promise<string> {
  validateScope(sourceScope, { columns: options.columns, actions: options.actions });

  const sourcePayload = decodeJwt(sourceCredentialJwt).payload;
  const sourceChain = sourcePayload.delegationChain;
  if (Array.isArray(sourceChain) && sourceChain.length === 0) {
    throw new Error(
      'Delegation error: source credential has an empty delegationChain. ' +
        'A delegated credential must have at least one ancestor in the chain.',
    );
  }
  const rawType = sourcePayload.vc?.type;
  const sourceVcType: unknown[] = Array.isArray(rawType)
    ? rawType
    : typeof rawType === 'string' ? [rawType] : [];
  if (isDelegatedScopeCredentialType(sourceVcType)) {
    throw new Error(
      'Delegation error: source credential is itself delegated. Re-delegation is not permitted.',
    );
  }

  const chainPayloads = Array.isArray(sourceChain)
    ? sourceChain.map((jwt) => decodeJwt(jwt as string).payload)
    : [];
  const inheritedMaxDepth = resolveInheritedMaxDepth(sourcePayload, chainPayloads);

  const effectiveDepth = chainPayloads.length + 1;
  validateChain(effectiveDepth, inheritedMaxDepth);

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
    maxDepth: inheritedMaxDepth,
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

  return await delegatorSigner.signJwt(payload);
}

/** Issue an agent credential through an AbaxxOne parent instance. */
export async function issueCredentialFromParent(
  provider: {
    requestAgentCredential: (
      accessToken: string,
      agentDid: string,
      options: { columns: string[]; actions: string[]; expiresIn: string | number; maxDepth?: number },
    ) => Promise<{ jwt: string; issuerDid: string }>;
  },
  accessToken: string,
  agentDid: string,
  options: { columns: string[]; actions: string[]; expiresIn: string | number; maxDepth?: number },
  opts?: { ceiling?: ScopeCeiling; context?: IssuanceContext },
): Promise<{ jwt: string; issuerDid: string }> {
  if (options.maxDepth !== undefined) {
    if (!Number.isInteger(options.maxDepth) || options.maxDepth < 1) {
      throw new Error(
        `issueCredentialFromParent: maxDepth must be a positive integer, received ${String(options.maxDepth)}.`,
      );
    }
  }
  if (opts?.ceiling) {
    assertScopeFitsInCeiling(
      { columns: options.columns, actions: options.actions },
      opts.ceiling,
      opts.context,
    );
    if (opts.ceiling.credentialMaxTtlMs !== undefined) {
      assertExpiresInBound(options.expiresIn, opts.ceiling.credentialMaxTtlMs);
    }
  }
  return provider.requestAgentCredential(accessToken, agentDid, options);
}
