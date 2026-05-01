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
 * OrgBoundary — extracts organizational identity from OIDC claims.
 *
 * Pure utility (no network, no state). Consumer-domain exclusions (gmail.com, etc.) are
 * built-in; extended via the `extraConsumerDomains` parameter sourced from
 * `AgentScopeConfig.orgBoundary.extraConsumerDomains`. Consumers must thread the SAME list
 * to both OrgBoundary and GenericOidcProvider so the two engines agree byte-for-byte.
 *
 * Extraction priority: hd (Google Workspace) → tid (Azure AD) → org claim → email domain fallback.
 */

import type { OidcIdentity } from '../auth/provider.js';

// ─── Consumer Domain Registry ────────────────────────────────────────────────

/**
 * Built-in consumer domains (gmail.com, hotmail.com, etc.) — not enterprise orgs.
 *
 * Returned by reference when no extraConsumerDomains are supplied. Object.freeze is a no-op for
 * Set mutating methods in V8 (they access internal state, not object properties), so the mutating
 * methods are overridden to throw TypeError — giving both compile-time and runtime safety.
 */
function _buildFrozenBuiltIn(): ReadonlySet<string> {
  const set = new Set([
    // Google consumer
    'gmail.com',
    'googlemail.com',
    // Microsoft consumer
    'hotmail.com',
    'outlook.com',
    'live.com',
    'msn.com',
    // Apple consumer
    'icloud.com',
    'me.com',
    'mac.com',
    // Yahoo
    'yahoo.com',
    'yahoo.co.uk',
    'yahoo.fr',
    'yahoo.de',
    // AOL
    'aol.com',
    // Privacy-focused (not enterprise)
    'protonmail.com',
    'proton.me',
    'tutanota.com',
    'tutamail.com',
    // Other common consumer
    'zoho.com',
    'mail.com',
    'inbox.com',
  ]);
  const guard = (op: string) => () => {
    throw new TypeError(
      `BUILT_IN_CONSUMER_DOMAINS is read-only — refusing ${op}(). ` +
        'To add caller-specific consumer domains, pass them via the ' +
        '`extraConsumerDomains` parameter on the public OrgBoundary static methods ' +
        '(or via AgentScopeConfig.orgBoundary.extraConsumerDomains).',
    );
  };
  set.add = guard('add') as typeof set.add;
  set.delete = guard('delete') as typeof set.delete;
  set.clear = guard('clear') as typeof set.clear;
  return set;
}
const BUILT_IN_CONSUMER_DOMAINS: ReadonlySet<string> = _buildFrozenBuiltIn();

/**
 * Compose the built-in consumer-domain registry with caller-supplied extensions.
 * Pure function — no env-read, no cache. Returns the frozen built-in by reference when
 * no extensions are supplied (zero allocation). Exported so GenericOidcProvider can reuse
 * it and agree with OrgBoundary byte-for-byte.
 */
export function composeConsumerDomains(
  extraConsumerDomains?: readonly string[],
): ReadonlySet<string> {
  if (!extraConsumerDomains || extraConsumerDomains.length === 0) {
    return BUILT_IN_CONSUMER_DOMAINS;
  }
  const combined = new Set<string>(BUILT_IN_CONSUMER_DOMAINS);
  for (const d of extraConsumerDomains) {
    if (typeof d !== 'string') continue;
    const trimmed = d.trim().toLowerCase();
    if (trimmed) combined.add(trimmed);
  }
  return combined;
}

// ─── OrgBoundary ─────────────────────────────────────────────────────────────

export interface OrgBoundaryResult {
  /** The extracted org identifier. null if no org could be determined. */
  org: string | null;
  /** How the org was determined — useful for audit logs and debugging. */
  source: 'hd' | 'tid' | 'org_claim' | 'email_domain' | 'none';
  /** True if this identity is from an enterprise account. False for consumers. */
  isEnterprise: boolean;
}

export class OrgBoundary {
  /**
   * Extract the organizational identity from an OidcIdentity.
   *
   * Pure function — no network, no state, deterministic. Operates on the
   * OidcIdentity produced by OidcProvider.fetchUserInfo() or
   * parseIdentityFromToken().
   *
   * @param identity  The OidcIdentity to extract org from.
   * @param extraConsumerDomains  Optional extension of the built-in
   *   consumer-domain registry. Sourced from
   *   `AgentScopeConfig.orgBoundary.extraConsumerDomains`. When omitted,
   *   only the built-in domains are excluded.
   */
  static extract(
    identity: Pick<OidcIdentity, 'email' | 'org' | 'claims'>,
    extraConsumerDomains?: readonly string[],
  ): OrgBoundaryResult {
    const claims = identity.claims;
    const consumerDomains = composeConsumerDomains(extraConsumerDomains);

    // 1. Google Workspace hosted domain (hd claim) — most authoritative
    const hd = claims.hd;
    if (typeof hd === 'string' && hd.trim()) {
      return { org: hd.toLowerCase(), source: 'hd', isEnterprise: true };
    }

    // 2. Azure AD tenant ID (tid claim)
    const tid = claims.tid;
    if (typeof tid === 'string' && tid.trim()) {
      return { org: tid, source: 'tid', isEnterprise: true };
    }

    // 3. Explicit org claim (AbaxxOne and some enterprise providers)
    const orgClaim = identity.org ?? (typeof claims.org === 'string' ? claims.org : undefined);
    if (orgClaim && orgClaim.trim()) {
      return { org: orgClaim.toLowerCase(), source: 'org_claim', isEnterprise: true };
    }

    // 4. Email domain fallback — only if not a consumer domain
    const email = identity.email;
    if (email) {
      const domain = email.split('@')[1]?.toLowerCase();
      if (domain && !consumerDomains.has(domain)) {
        return { org: domain, source: 'email_domain', isEnterprise: true };
      }
    }

    // No org determinable — consumer account or missing claims
    return { org: null, source: 'none', isEnterprise: false };
  }

  /**
   * Assert that an identity belongs to a specific org.
   * Returns true if the extracted org matches (case-insensitive).
   *
   * Used by Layer 2 verification to enforce org-scoped resource access.
   * An agent presenting a credential must prove it belongs to the same org
   * as the resource owner.
   *
   * @param identity  The identity to check.
   * @param expectedOrg  The org identifier to assert membership in.
   * @param extraConsumerDomains  Optional extension of the consumer-domain
   *   registry. Should be the same value the consumer threads to
   *   `OrgBoundary.extract()` and `GenericOidcProvider` to keep the two
   *   engines' boundaries consistent.
   */
  static assertMembership(
    identity: Pick<OidcIdentity, 'email' | 'org' | 'claims'>,
    expectedOrg: string,
    extraConsumerDomains?: readonly string[],
  ): boolean {
    const result = OrgBoundary.extract(identity, extraConsumerDomains);
    if (!result.org) return false;
    return result.org.toLowerCase() === expectedOrg.toLowerCase();
  }

  /**
   * Check whether an email address is a consumer address (not enterprise).
   * Thin utility used by GenericOidcProvider and OrgBoundary.extract().
   *
   * @param email  The email address to check.
   * @param extraConsumerDomains  Optional extension of the consumer-domain
   *   registry. Same source as `extract()` / `assertMembership()`.
   */
  static isConsumerEmail(email: string, extraConsumerDomains?: readonly string[]): boolean {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return true; // malformed email → treat as consumer
    return composeConsumerDomains(extraConsumerDomains).has(domain);
  }
}
