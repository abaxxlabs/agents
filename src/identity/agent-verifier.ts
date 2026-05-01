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
 * AgentVerifier — mandatory Layer 2 orchestrator for MCP agent authentication.
 *
 * Any caller that only runs Layer 1 (crypto) has a security hole: a valid VC from an untrusted
 * issuer, wrong org, or missing capability passes signature checks and still gets in.
 * AgentVerifier closes that gap as the single place that runs all four checks in sequence.
 *
 * Layer 1 — VcVerifier: pure cryptographic verification — no trust policy, no org, no capabilities.
 *            Can be reused in non-MCP contexts (CLI verify) where server-specific policy must NOT apply.
 * Layer 2 — AgentVerifier: runs four checks in sequence on the same verified claims:
 *   1. VcVerifier.verify() — signature, expiry, nbf, subject binding, replay, revocation
 *   2. TrustAnchorStore.isTrusted(issuerDid) → UntrustedIssuerError
 *   3. Org boundary check → WrongOrgError (optional — caller passes expectedOrg)
 *   4. CapabilityEngine.checkCapability() → AgentUnauthorizedError (optional — caller passes action)
 *
 * MCP handlers MUST call AgentVerifier.verify() — NOT VcVerifier.verify() directly.
 * Bypassing AgentVerifier skips trust-anchor and org checks: any server with a valid Ed25519 key
 * could issue binding VCs that pass Layer 1 and access org-scoped resources.
 *
 * Checks MUST run in this order. Trust-anchor check before Layer 1 is wrong — a forged DID
 * string must be cryptographically proven before policy decisions are made on it.
 */

import { VcVerifier, decodeJwt } from '../vc-verifier.js';
import type { VerificationResult, VerifyOptions, DecodedCredential } from '../types.js';
import type { TrustAnchorStore } from '../discovery/trust-anchor.js';
import { CapabilityEngine } from '../capability/engine.js';
import type { CapabilitySet } from '../capability/types.js';
import {
  AgentScopeError,
  CredentialInvalidError,
  CredentialMalformedError,
  UnknownIssuerError,
} from '../errors.js';

// ─── Layer 2 Error Types ──────────────────────────────────────────────────────

/**
 * UntrustedIssuerError — thrown when the binding credential's issuer DID is not
 * in the server's TrustAnchorStore.
 *
 * Distinct from UnknownIssuerError (which is a DID resolution failure — Layer 1).
 * Here the DID was resolved successfully (signature verified), but the server has
 * not been configured to trust credentials from this issuer. This is a policy
 * failure, not a crypto failure. Callers debugging 401s should look at the
 * TrustAnchorStore configuration, not the agent's keys.
 *
 * Code: 'UNTRUSTED_ISSUER' — distinct from 'UNKNOWN_ISSUER' (DID resolution).
 */
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

/**
 * WrongOrgError — thrown when the binding credential's orgDomain does not match
 * the server's expected org.
 *
 * Triggered by Layer 2b (org boundary check). The credential may be
 * cryptographically valid and from a trusted issuer, but if the agent's org does
 * not match the resource owner's org, access is denied. This is the enforcement
 * point for org-scoped resource isolation — without it, a trusted server in
 * org-A could issue binding VCs granting access to org-B resources.
 *
 * Code: 'WRONG_ORG'
 */
export class WrongOrgError extends AgentScopeError {
  constructor(
    issuerDid: string,
    subjectDid: string,
    actualOrg: string | null,
    expectedOrg: string,
  ) {
    super(
      'WRONG_ORG',
      `Org boundary mismatch — expected '${expectedOrg}', got '${actualOrg ?? 'none'}'. ` +
        `Issuer: ${issuerDid}, Subject: ${subjectDid}.`,
      { issuerDid, subjectDid, actualOrg, expectedOrg },
    );
    this.name = 'WrongOrgError';
  }
}

/**
 * AgentUnauthorizedError — thrown when the binding credential's capability set
 * does not permit the requested action+scope.
 *
 * Triggered by Layer 2c (capability check). The credential is valid, the issuer
 * is trusted, the org matches, but the agent does not hold the capability for
 * the requested action. Denial reasons identify the denied action and resource
 * only — they do NOT enumerate the full granted capability set (oracle risk).
 *
 * Code: 'UNAUTHORIZED'
 */
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

/**
 * ParentScopeExceededError — thrown when an agent's capabilities exceed what
 * the parent instance authorized.
 *
 * Triggered by Step 2.5 (parent scope ceiling check). When AbaxxOne issues a
 * credential with specific capabilities, agents operating under that parent
 * must not exceed those capabilities. This is the enforcement point: even if
 * the credential is valid, trusted, and from the right org, its capabilities
 * must be a subset of what the parent authorized.
 *
 * Includes requestedCapabilities and parentCeiling in error details for
 * developer diagnostics — helps debug "why was my agent denied?" without
 * requiring log correlation.
 *
 * Code: 'PARENT_SCOPE_EXCEEDED'
 */
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

// ─── Request / Result Types ───────────────────────────────────────────────────

/**
 * Input to AgentVerifier.verify(). All four Layer 2 checks are driven by fields
 * on this request. Optional fields enable/disable the corresponding check.
 */
export interface AgentVerifyRequest {
  /**
   * The binding credential JWT to verify.
   *
   * Must be a JWT-encoded IdentityBindingCredential or compatible VC. Passed
   * directly to VcVerifier for Layer 1 crypto verification.
   */
  bindingJwt: string;

  /**
   * DID of the agent making the request — for subject binding check.
   *
   * Required. VcVerifier asserts payload.sub === agentDid after signature
   * validation. This prevents confused-deputy attacks where agent-B presents
   * a valid VC issued for agent-A. Without this check, any agent holding a
   * valid VC (regardless of who it was issued for) could pass Layer 1.
   *
   * Security note: making this required at the TypeScript type level is
   * intentional. An optional field
   * creates a silent bypass path — callers that forget to set it skip subject
   * binding without any indication. Required fields surface omissions as
   * compile-time errors rather than runtime auth gaps.
   *
   * MCP handlers: set this to the DID extracted from the agent's authentication
   * header (or from the binding JWT's sub claim before full verification, then
   * verify that they match post-signature).
   */
  agentDid: string;

  /**
   * Assert that the credential's orgDomain matches this value (case-insensitive).
   *
   * When set, Layer 2b checks orgDomain from the credential subject. If the
   * credential's orgDomain is null (consumer account) or doesn't match, throws
   * WrongOrgError. If not set, org check is skipped.
   *
   * Obtain from OrgBoundary.extract() on your server's configured identity, or
   * from the AGENTS_ORG env var.
   */
  expectedOrg?: string;

  /**
   * Check that this action is permitted by the credential's capability set.
   *
   * When set, Layer 2c calls CapabilityEngine.checkCapability(action, scope, caps)
   * against the credential subject's `capabilities` field. If the action is not
   * permitted, throws AgentUnauthorizedError. If not set, capability check is skipped.
   *
   * Must be a valid CapabilityAction string (ASCII printable, max 256 chars).
   * Throws CapabilityParseError (from CapabilityEngine) if malformed — this is
   * a caller programming error, not an auth failure.
   */
  action?: string;

  /**
   * Resource scope for the capability check. Only meaningful alongside `action`.
   *
   * Passed as-is to CapabilityEngine.checkCapability(). If the credential's
   * capability for the action has a scope restriction, it must match exactly.
   */
  scope?: string;

  /**
   * Parent scope ceiling — the maximum capability set authorized by the parent
   * instance. When set, Step 2.5 asserts that the credential's capabilities are
   * a subset of this ceiling using CapabilityEngine.isSubsetOf().
   *
   * When running under an AbaxxOne parent instance, the parent credential defines
   * the maximum scope. An agent cannot exceed what the org authorized, even if
   * the binding credential's capability set is broader.
   *
   * Set by MCP bearer auth middleware when the session's parentIssuerDid is present.
   * The ceiling is extracted from the parent credential's capability claims.
   * Not set for free-tier sessions (no parent, no ceiling).
   */
  parentScopeCeiling?: CapabilitySet;
}

/**
 * Result of a successful AgentVerifier.verify() call.
 *
 * All four Layer 2 checks passed. The caller can use these fields to set up
 * request context for downstream handlers.
 */
export interface AgentVerifyResult {
  /** DID of the issuer (the server that issued the binding credential). Trusted per Layer 2a. */
  issuerDid: string;
  /** DID of the subject (the agent whose identity is bound). Subject-bound per Layer 1. */
  subjectDid: string;
  /**
   * Org domain from the credential subject (e.g., 'company.com', Azure tenant GUID).
   * null for consumer accounts or when orgDomain is absent from the credential.
   * Matched against expectedOrg in Layer 2b.
   */
  orgDomain: string | null;
  /**
   * Capabilities from the credential subject. Empty array if not present.
   * Used by Layer 2c for capability checks. Available to downstream handlers
   * for subsequent action checks without re-parsing the JWT.
   */
  capabilities: CapabilitySet;
  /** Full decoded credential from VcVerifier Layer 1. */
  credential: DecodedCredential;
}

// ─── AgentVerifier interface ─────────────────────────────────────────────────

/**
 * AgentVerifier — the contract for Layer 2 agent auth orchestration.
 *
 * Depend on this interface, not AgentVerifier, so tests can inject stubs and
 * future implementations can swap in alternative auth mechanisms without
 * changing calling code.
 *
 * @see AgentVerifier — concrete implementation
 * @see createAgentVerifier — factory
 */
export interface AgentVerifier {
  /**
   * Verify an agent's binding credential through all four checks.
   *
   * Throws on any failure — callers should catch specific error types:
   *   - CredentialInvalidError: Layer 1 failure (signature, expiry, replay, wrong subject)
   *   - CredentialMalformedError: Layer 1 failure (invalid JWT structure)
   *   - UnknownIssuerError: Layer 1 failure (DID resolution failed)
   *   - UntrustedIssuerError: Layer 2a failure (issuer not in trust anchor store)
   *   - ParentScopeExceededError: Layer 2a.5 failure (capabilities exceed parent ceiling)
   *   - WrongOrgError: Layer 2b failure (org mismatch)
   *   - AgentUnauthorizedError: Layer 2c failure (action not permitted)
   *   - CapabilityParseError: Layer 2c caller error (malformed action string)
   *
   * Returns AgentVerifyResult on success — all four checks passed.
   */
  verify(request: AgentVerifyRequest): Promise<AgentVerifyResult>;
}

// ─── AgentVerifierOptions ─────────────────────────────────────────────────────

/**
 * Options for constructing an AgentVerifier.
 *
 * vcVerifier and trustAnchorStore are required — they are the Layer 1 and Layer 2a
 * primitives respectively. capabilityEngine is optional; if not provided, a default
 * instance is created. All three are designed to be shared (no per-request state).
 */
export interface AgentVerifierOptions {
  /**
   * VcVerifier instance for Layer 1 cryptographic verification.
   *
   * Share this with other callers — VcVerifier holds a DID resolution cache and
   * a replay protection cache. Creating a new instance per request throws away
   * both caches and defeats the purpose of replay protection.
   *
   * CRITICAL: MCP handlers must NEVER call vcVerifier.verify() directly. They
   * must always go through AgentVerifier.verify() so that Layer 2 checks run.
   */
  vcVerifier: VcVerifier;

  /**
   * TrustAnchorStore for Layer 2a trust anchor check.
   *
   * isTrusted() is O(1). Safe to call on every MCP request hot path.
   * The own server's DID is always in the store (source: 'local').
   */
  trustAnchorStore: TrustAnchorStore;

  /**
   * CapabilityEngine for Layer 2c capability check.
   *
   * Optional — if not provided, a default CapabilityEngine is created. CapabilityEngine
   * holds no state, so sharing one instance is fine, but there is no cost to
   * creating a new one if that is more ergonomic in the caller's context.
   */
  capabilityEngine?: CapabilityEngine;
}

// ─── AgentVerifier ────────────────────────────────────────────────────────────

/**
 * AgentVerifier — the mandatory single door for MCP agent authentication.
 *
 * See module-level JSDoc for the full architectural rationale. Usage:
 *
 *   const verifier = createAgentVerifier({ vcVerifier, trustAnchorStore });
 *
 *   // In MCP bearer auth middleware:
 *   const result = await verifier.verify({
 *     bindingJwt: bearer,
 *     agentDid: requestingAgentDid,
 *     expectedOrg: 'company.com',
 *   });
 *   // result.issuerDid, result.orgDomain, result.capabilities available
 *
 *   // In a capability-gated MCP tool handler:
 *   await verifier.verify({
 *     bindingJwt: bearer,
 *     agentDid: requestingAgentDid,
 *     action: 'jira:read',
 *     scope: 'project/PROJ',
 *   });
 *
 * @implements AgentVerifier
 */
export class AgentVerifier implements AgentVerifier {
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

  /**
   * Verify an agent's binding credential through all four checks in sequence.
   *
   * Check sequence:
   *   1. VcVerifier.verify() — crypto (signature, expiry, nbf, subject binding, replay)
   *   2. TrustAnchorStore.isTrusted(issuerDid) — policy: issuer must be known + trusted
   *   3. Org boundary check — policy: orgDomain must match expectedOrg (if provided)
   *   4. CapabilityEngine.checkCapability() — authz: action must be in capability set (if provided)
   *
   * Security: checks run in this exact order. Layer 1 must succeed before Layer 2
   * policy decisions are made — a forged DID string must not be trusted before
   * its cryptographic identity is established.
   */
  async verify(request: AgentVerifyRequest): Promise<AgentVerifyResult> {
    // Empty string satisfies the TypeScript type but would bypass subject binding in VcVerifier.
    if (!request.agentDid) {
      throw new TypeError(
        'AgentVerifier: agentDid must be a non-empty string — ' +
          "callers must supply the requesting agent's DID to enable subject binding",
      );
    }

    // ── Step 1 (Layer 1): Cryptographic verification ────────────────────────
    const vcOptions: VerifyOptions = {
      skipScopeCheck: true, // binding VCs carry no scope.columns
      expectedSubject: request.agentDid,
    };

    const vcResult = await this.vcVerifier.verify(request.bindingJwt, vcOptions);

    if (!vcResult.valid || !vcResult.credential) {
      throw mapVcVerifierError(vcResult, request.agentDid);
    }

    const { issuer: issuerDid, subject: subjectDid } = vcResult.credential;

    // ── Decode credential subject ───────────────────────────────────────────
    // orgDomain and capabilities are in the raw JWT's vc.credentialSubject, not DecodedCredential.
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
      // SDK-backed path may accept JWTs our decodeJwt() cannot parse.
      // Reject rather than silently continue with null orgDomain + empty capabilities (fail-open).
      // Error message is sanitized — decodeJwt() errors may echo JWT fragments.
      throw new CredentialMalformedError(
        'Binding credential passed signature verification but credentialSubject could not be parsed',
      );
    }

    // ── Step 2 (Layer 2a): Trust anchor check ──────────────────────────────
    // The issuer DID must be in the trust anchor store. Even if Layer 1 succeeds (signature
    // is valid), we only accept credentials from explicitly trusted issuers. Without this,
    // any server with a valid Ed25519 key pair could issue binding VCs that grant access.
    // O(1) — must not block. Safe on the hot path of every MCP request.
    if (!this.trustAnchorStore.isTrusted(issuerDid)) {
      throw new UntrustedIssuerError(issuerDid);
    }

    // ── Step 2.5 (Layer 2a.5): Parent scope ceiling check ──────────────────
    if (request.parentScopeCeiling) {
      if (!this.capabilityEngine.isSubsetOf(capabilities, request.parentScopeCeiling)) {
        throw new ParentScopeExceededError(capabilities, request.parentScopeCeiling);
      }
    }

    // ── Step 3 (Layer 2b): Org boundary check ──────────────────────────────
    if (request.expectedOrg !== undefined) {
      // Trim whitespace — an invisible trailing space in an env var would cause WrongOrgError
      // for every agent in the org, with a log message that looks identical to a match.
      const normalizedExpectedOrg = request.expectedOrg.trim();
      if (!normalizedExpectedOrg) {
        // Empty/whitespace-only expectedOrg is a caller programming error.
        throw new TypeError(
          'AgentVerifier: expectedOrg must not be empty or whitespace-only — ' +
            'check your AGENTS_ORG config or the value passed to verify()',
        );
      }
      const orgMatch =
        orgDomain !== null && orgDomain.toLowerCase() === normalizedExpectedOrg.toLowerCase();
      if (!orgMatch) {
        throw new WrongOrgError(issuerDid, subjectDid, orgDomain, normalizedExpectedOrg);
      }
    }

    // ── Step 4 (Layer 2c): Capability check ────────────────────────────────
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

// ─── VcVerifier error mapping ─────────────────────────────────────────────────

/**
 * Map a failed VerificationResult to the appropriate AgentScopeError.
 *
 * MALFORMED → CredentialMalformedError: structural problem in the JWT.
 * UNKNOWN_ISSUER → UnknownIssuerError: DID resolution failure (distinct from
 *   UNTRUSTED_ISSUER, which is a policy failure after successful resolution).
 * Everything else → CredentialInvalidError with the status code in the message.
 *   This covers EXPIRED, REVOKED, SUSPENDED, INVALID_SIGNATURE, REPLAYED, WRONG_SUBJECT.
 *   Including the status code aids debugging without requiring a separate error class for each.
 */
function mapVcVerifierError(result: VerificationResult, agentDid: string): AgentScopeError {
  const msg = result.error ?? `Credential verification failed: ${result.status}`;

  if (result.status === 'MALFORMED') {
    return new CredentialMalformedError(msg);
  }

  if (result.status === 'UNKNOWN_ISSUER') {
    return new UnknownIssuerError(agentDid, msg);
  }

  return new CredentialInvalidError(agentDid, `[${result.status}] ${msg}`);
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * createAgentVerifier — convenience factory for AgentVerifier.
 *
 * Prefer this over `new AgentVerifier()` in application code so the instantiation
 * site can be mocked in tests. Returns an AgentVerifier typed as AgentVerifier
 * so callers depend on the interface, not the class.
 *
 * @example
 *   const verifier = createAgentVerifier({ vcVerifier, trustAnchorStore });
 *   // In MCP request handler:
 *   const result = await verifier.verify({ bindingJwt: bearer, agentDid: agentDid });
 */
export function createAgentVerifier(options: AgentVerifierOptions): AgentVerifier {
  return new AgentVerifier(options);
}
