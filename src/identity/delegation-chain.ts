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

import type { RevocationStore } from '#storage/types.js';
import type { VerificationResult, IdSdkInstance } from '#types/index.js';
import { decodeJwt, verifyJwtSignature } from '#crypto/jwt.js';
import { isDelegatedScopeCredentialType } from '#auth/credential-issuance.js';
import { DEFAULT_MAX_DELEGATION_DEPTH, extractMaxDepth } from '#auth/delegation-policy.js';
import { base58Decode } from '#crypto/base58.js';
import type { RevocationTelemetryEvent } from './vc-verifier.js';

const MAX_CHAIN_DEPTH = 10;

export async function resolveRegisteredIssuerKey(
  did: string,
  knownKeys: Map<string, Uint8Array>,
  sdk?: IdSdkInstance,
): Promise<Uint8Array | null> {
  const known = knownKeys.get(did);
  if (known) return known;
  if (!sdk) return null;
  try {
    const result = await sdk.did.resolve(did);
    const doc = result.didDocument as
      | {
          verificationMethod?: Array<{
            publicKeyJwk?: { x: string };
            publicKeyMultibase?: string;
          }>;
        }
      | undefined;
    const vm = doc?.verificationMethod?.[0];
    if (!vm) return null;
    if (vm.publicKeyJwk) {
      return new Uint8Array(Buffer.from(vm.publicKeyJwk.x, 'base64url'));
    }
    if (vm.publicKeyMultibase) {
      const encoded = vm.publicKeyMultibase.slice(1);
      const pk = base58Decode(encoded);
      return pk[0] === 0xed && pk[1] === 0x01 ? pk.slice(2) : pk;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Enforce the embedded maxDepth ceiling at verification time. Returns a
 * `POLICY_VIOLATION` result when the chain's depth meets or exceeds the
 * smallest maxDepth declared across the leaf and its ancestors; undefined when
 * within the ceiling or the credential is not delegated.
 *
 * @param payload  The decoded leaf credential JWT payload.
 */
export function checkDelegationDepthCeiling(payload: {
  maxDepth?: unknown;
  delegationChain?: unknown;
}): VerificationResult | undefined {
  const rootChain = payload.delegationChain;
  if (!Array.isArray(rootChain) || rootChain.length === 0) return undefined;

  const cursor: string[] = rootChain.filter((j): j is string => typeof j === 'string');
  if (cursor.length === 0) {
    return {
      valid: false,
      status: 'MALFORMED',
      error: 'delegationChain contains no valid JWT entries',
    };
  }

  let ceiling = extractMaxDepth(payload) ?? DEFAULT_MAX_DELEGATION_DEPTH;
  let depth = 0;
  let current = cursor;
  let totalNodes = 0;

  while (current.length > 0) {
    depth++;
    if (depth > MAX_CHAIN_DEPTH) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: `Delegation chain exceeds maximum depth of ${MAX_CHAIN_DEPTH}`,
      };
    }
    const next: string[] = [];
    for (const ancestorJwt of current) {
      if (++totalNodes > MAX_CHAIN_DEPTH) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: `Delegation chain exceeds maximum total nodes of ${MAX_CHAIN_DEPTH}`,
        };
      }
      let ancestorPayload: ReturnType<typeof decodeJwt>['payload'];
      try {
        ancestorPayload = decodeJwt(ancestorJwt).payload;
      } catch {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'Delegation chain contains malformed JWT',
        };
      }
      const ancestorCeiling = extractMaxDepth(ancestorPayload) ?? DEFAULT_MAX_DELEGATION_DEPTH;
      if (ancestorCeiling < ceiling) ceiling = ancestorCeiling;
      if (Array.isArray(ancestorPayload.delegationChain)) {
        for (const inner of ancestorPayload.delegationChain) {
          if (typeof inner === 'string') next.push(inner);
        }
      }
    }
    current = next;
  }

  if (depth >= ceiling) {
    return {
      valid: false,
      status: 'POLICY_VIOLATION',
      error: `Delegation chain depth ${depth} exceeds maximum delegation depth ${ceiling}.`,
    };
  }
  return undefined;
}

export async function checkDelegationChainRevocation(
  rootChain: unknown,
  deps: {
    revocationStore: RevocationStore;
    knownKeys: Map<string, Uint8Array>;
    sdk?: IdSdkInstance;
    emitRevocationTelemetry(event: RevocationTelemetryEvent): void;
  },
): Promise<VerificationResult | undefined> {
  if (!Array.isArray(rootChain) || rootChain.length === 0) return undefined;

  let cursor: string[] = rootChain.filter((j): j is string => typeof j === 'string');
  if (cursor.length === 0) {
    return {
      valid: false,
      status: 'MALFORMED',
      error: 'delegationChain contains no valid JWT entries',
    };
  }

  let depth = 0;
  let totalNodes = 0;

  while (cursor.length > 0) {
    if (++depth > MAX_CHAIN_DEPTH) {
      return {
        valid: false,
        status: 'MALFORMED',
        error: `Delegation chain exceeds maximum depth of ${MAX_CHAIN_DEPTH}`,
      };
    }
    const next: string[] = [];
    for (const ancestorJwt of cursor) {
      if (++totalNodes > MAX_CHAIN_DEPTH) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: `Delegation chain exceeds maximum total nodes of ${MAX_CHAIN_DEPTH}`,
        };
      }
      let ancestorPayload: ReturnType<typeof decodeJwt>['payload'];
      try {
        ancestorPayload = decodeJwt(ancestorJwt).payload;
      } catch {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'Delegation chain contains malformed JWT',
        };
      }

      if (!ancestorPayload.iss) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'Delegation chain ancestor missing issuer (iss) claim',
        };
      }
      const ancestorKey = await resolveRegisteredIssuerKey(
        ancestorPayload.iss,
        deps.knownKeys,
        deps.sdk,
      );
      if (!ancestorKey) {
        return {
          valid: false,
          status: 'UNKNOWN_ISSUER',
          error: 'Delegation chain ancestor issuer not registered',
        };
      }
      if (!(await verifyJwtSignature(ancestorJwt, ancestorKey))) {
        return {
          valid: false,
          status: 'INVALID_SIGNATURE',
          error: 'Delegation chain ancestor signature invalid',
        };
      }

      const rawAncestorType = ancestorPayload.vc?.type;
      const ancestorVcType: unknown[] = Array.isArray(rawAncestorType)
        ? rawAncestorType
        : typeof rawAncestorType === 'string'
          ? [rawAncestorType]
          : [];
      if (isDelegatedScopeCredentialType(ancestorVcType)) {
        return {
          valid: false,
          status: 'MALFORMED',
          error: 'Delegation chain contains a re-delegated credential.',
        };
      }
      if (ancestorPayload.jti) {
        let ancestorRevoked: boolean;
        try {
          ancestorRevoked = await deps.revocationStore.isRevoked(ancestorPayload.jti);
        } catch (err) {
          deps.emitRevocationTelemetry({
            source: 'local_store',
            credentialId: ancestorPayload.jti,
            outcome: 'failed',
            error: err,
          });
          throw err;
        }
        deps.emitRevocationTelemetry({
          source: 'local_store',
          credentialId: ancestorPayload.jti,
          outcome: ancestorRevoked ? 'revoked' : 'not_revoked',
        });
        if (ancestorRevoked) {
          return {
            valid: false,
            status: 'REVOKED',
            error: `Delegation chain credential ${ancestorPayload.jti} has been revoked`,
          };
        }
      }
      if (Array.isArray(ancestorPayload.delegationChain)) {
        for (const inner of ancestorPayload.delegationChain) {
          if (typeof inner === 'string') next.push(inner);
        }
      }
    }
    cursor = next;
  }
  return undefined;
}
