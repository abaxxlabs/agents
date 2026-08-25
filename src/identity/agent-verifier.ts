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

import { VcVerifier } from './vc-verifier.js';
import { decodeJwt } from '#crypto/jwt.js';
import type { VerificationResult, VerifyOptions, DecodedCredential } from '#types/index.js';
import type { TrustAnchorStore } from '#discovery/trust-anchor.js';
import { CapabilityEngine } from '#capability/engine.js';
import type { CapabilitySet } from '#capability/types.js';
import {
  AgentScopeError,
  CredentialInvalidError,
  CredentialMalformedError,
  UnknownIssuerError,
} from '#errors/index.js';

/** Issuer DID is not in the TrustAnchorStore. Distinct from UnknownIssuerError (DID resolution failure). */
export class UntrustedIssuerError extends AgentScopeError {
  constructor(issuerDid: string) {
    super(
      'UNTRUSTED_ISSUER',
      `Issuer DID '${issuerDid}' is not in the trust anchor store. ` +
        'Add it via TrustAnchorStore.addTrustedServer(), or seed the store at ' +
        'construction time with `initialTrustedServers` (the bootstrap helper ' +
        '`resolveTrustedServersFromEnv()` from `@abaxxlabs/agents/bootstrap` reads ' +
        '`AGENTS_TRUSTED_SERVERS` for you and returns the parsed list).',
      { issuerDid },
    );
    this.name = 'UntrustedIssuerError';
  }
}

/** Credential's orgDomain does not match the server's expected org. */
export class WrongOrgError extends AgentScopeError {
  constructor(
    issuerDid: string,
    subjectDid: string,
    actualOrg: string | null,
    expectedOrg: string,
  ) {
    super(
      'WRONG_ORG',
      `Org boundary mismatch: expected '${expectedOrg}', got '${actualOrg ?? 'none'}'. ` +
        `Issuer: ${issuerDid}, Subject: ${subjectDid}.`,
      { issuerDid, subjectDid, actualOrg, expectedOrg },
    );
    this.name = 'WrongOrgError';
  }
}

/** Credential's capability set does not permit the requested action+scope. */
export class AgentUnauthorizedError extends AgentScopeError {
  constructor(subjectDid: string, action: string, scope: string | undefined, reason: string) {
    super('UNAUTHORIZED', `Agent '${subjectDid}' is not authorized: ${reason}`, {
      subjectDid,
      action,
      scope,
    });
    this.name = 'AgentUnauthorizedError';
  }
}

/** Agent's capabilities exceed what the parent instance authorized. */
export class ParentScopeExceededError extends AgentScopeError {
  constructor(
    public readonly requestedCapabilities: CapabilitySet,
    public readonly parentCeiling: CapabilitySet,
  ) {
    super(
      'PARENT_SCOPE_EXCEEDED',
      'Agent capabilities exceed what the parent instance authorized. ' +
        'Request a credential with narrower scope, or ask your AbaxxOne administrator ' +
        "to expand the parent credential's capability set.",
      {
        requestedCapabilitiesCount: requestedCapabilities.length,
        parentCeilingCount: parentCeiling.length,
      },
    );
    this.name = 'ParentScopeExceededError';
  }
}

export interface AgentVerifyRequest {
  /** The binding credential JWT to verify. */
  bindingJwt: string;
  /** DID of the agent making the request. Required for subject binding check. */
  agentDid: string;
  /** Assert orgDomain matches this value (case-insensitive). Skipped if unset. */
  expectedOrg?: string;
  /** Check that this action is permitted by the credential's capability set. Skipped if unset. */
  action?: string;
  /** Resource scope for the capability check. Only meaningful alongside `action`. */
  scope?: string;
  /** Maximum capability set authorized by the parent instance. */
  parentScopeCeiling?: CapabilitySet;
}

export interface AgentVerifyResult {
  issuerDid: string;
  subjectDid: string;
  orgDomain: string | null;
  capabilities: CapabilitySet;
  credential: DecodedCredential;
}

export interface AgentVerifierOptions {
  vcVerifier: VcVerifier;
  trustAnchorStore: TrustAnchorStore;
  capabilityEngine?: CapabilityEngine;
}

/**
 * Layer 2 orchestrator for MCP agent auth. Runs four checks in sequence:
 * 1. VcVerifier.verify(): signature, strict VC timing, subject binding, and revocation
 * 2. TrustAnchorStore.isTrusted(): issuer must be known
 * 3. Org boundary: orgDomain must match expectedOrg
 * 4. CapabilityEngine: action must be in capability set
 */
export class AgentVerifier {
  private readonly vcVerifier: VcVerifier;
  private readonly trustAnchorStore: TrustAnchorStore;
  private readonly capabilityEngine: CapabilityEngine;

  constructor(options: AgentVerifierOptions) {
    if (!options.vcVerifier) {
      throw new TypeError('AgentVerifier: vcVerifier is required');
    }
    if (!options.trustAnchorStore) {
      throw new TypeError('AgentVerifier: trustAnchorStore is required');
    }

    this.vcVerifier = options.vcVerifier;
    this.trustAnchorStore = options.trustAnchorStore;
    this.capabilityEngine = options.capabilityEngine ?? new CapabilityEngine();
  }

  async verify(request: AgentVerifyRequest): Promise<AgentVerifyResult> {
    if (!request.agentDid) {
      throw new TypeError(
        'AgentVerifier: agentDid must be a non-empty string. ' +
          "callers must supply the requesting agent's DID to enable subject binding",
      );
    }

    const vcOptions: VerifyOptions = {
      skipScopeCheck: true,
      expectedSubject: request.agentDid,
    };

    const vcResult = await this.vcVerifier.verify(request.bindingJwt, vcOptions);

    if (!vcResult.valid || !vcResult.credential) {
      throw mapVcVerifierError(vcResult, request.agentDid);
    }

    const { issuer: issuerDid, subject: subjectDid } = vcResult.credential;

    let orgDomain: string | null = null;
    let capabilities: CapabilitySet = [];

    try {
      const { payload } = decodeJwt(request.bindingJwt);
      const cs = payload.vc?.credentialSubject;
      if (cs) {
        if (typeof cs['orgDomain'] === 'string') {
          orgDomain = cs['orgDomain'].trim() || null;
        }
        if (Array.isArray(cs['capabilities'])) {
          capabilities = cs['capabilities'] as CapabilitySet;
        }
      }
    } catch {
      throw new CredentialMalformedError(
        'Binding credential passed signature verification but credentialSubject could not be parsed',
      );
    }

    if (!this.trustAnchorStore.isTrusted(issuerDid)) {
      throw new UntrustedIssuerError(issuerDid);
    }

    if (request.parentScopeCeiling) {
      if (!this.capabilityEngine.isSubsetOf(capabilities, request.parentScopeCeiling)) {
        throw new ParentScopeExceededError(capabilities, request.parentScopeCeiling);
      }
    }

    if (request.expectedOrg !== undefined) {
      const normalizedExpectedOrg = request.expectedOrg.trim();
      if (!normalizedExpectedOrg) {
        throw new TypeError(
          'AgentVerifier: expectedOrg must not be empty or whitespace-only. ' +
            'check your AGENTS_ORG config or the value passed to verify()',
        );
      }
      const orgMatch =
        orgDomain !== null && orgDomain.toLowerCase() === normalizedExpectedOrg.toLowerCase();
      if (!orgMatch) {
        throw new WrongOrgError(issuerDid, subjectDid, orgDomain, normalizedExpectedOrg);
      }
    }

    if (request.action !== undefined) {
      const capResult = this.capabilityEngine.checkCapability(
        request.action,
        request.scope,
        capabilities,
      );
      if (!capResult.allowed) {
        throw new AgentUnauthorizedError(
          subjectDid,
          request.action,
          request.scope,
          capResult.reason,
        );
      }
    }

    return {
      issuerDid,
      subjectDid,
      orgDomain,
      capabilities,
      credential: vcResult.credential,
    };
  }
}

function mapVcVerifierError(result: VerificationResult, agentDid: string): AgentScopeError {
  const msg = result.error ?? `Credential verification failed: ${result.status}`;

  if (result.status === 'MALFORMED') {
    return new CredentialMalformedError(msg);
  }

  if (result.status === 'UNKNOWN_ISSUER') {
    return new UnknownIssuerError(agentDid, msg);
  }

  if (result.status === 'POLICY_VIOLATION') {
    return new CredentialInvalidError(agentDid, `[POLICY_VIOLATION] ${msg}`);
  }

  return new CredentialInvalidError(agentDid, `[${result.status}] ${msg}`);
}

export function createAgentVerifier(options: AgentVerifierOptions): AgentVerifier {
  return new AgentVerifier(options);
}
