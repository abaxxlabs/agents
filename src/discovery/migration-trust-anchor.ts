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
 * MigrationTrustAnchor — root of trust for identity migration credentials.
 *
 * Separate from LocalTrustAnchorStore because migration is a privileged identity-rebinding
 * operation. LocalTrustAnchorStore accepts runtime-configurable sources ('env', 'api') — a
 * forker who can flip AGENTS_TRUSTED_SERVERS into trusting their own DID would gain free
 * identity-rebinding capability if the migration executor used the same trust list.
 *
 * This class accepts only two sources, both out of reach of runtime configuration:
 *   'baked' — build-time OFFICIAL_MIGRATION_ISSUERS constant (source replacement, not config flip)
 *   'parent-credential-chain' — from a verified AbaxxOne parent credential; caller must verify first
 */

/**
 * Build-time-baked migration issuer DIDs.
 *
 * Empty by default — migration credentials are rejected in OSS builds. The AbaxxOne release
 * pipeline replaces this constant with canonical issuer DID(s). Override is intentionally NOT
 * via env var, constructor, or admin API — requires source replacement.
 *
 * Frozen array (not Set): Object.freeze does NOT intercept Set.prototype.add/delete/clear.
 * The constructor copies entries into #entries at construction so post-construction mutations
 * of this constant don't affect already-constructed instances.
 */
const OFFICIAL_MIGRATION_ISSUERS: readonly string[] = Object.freeze([
  // Empty in OSS source. AbaxxOne build pipeline bakes real issuer DID(s) here.
  // Example for AbaxxOne builds (replace at release time):
  //   'did:dht:<abaxxone-canonical-issuer-fingerprint>',
] as const);

/**
 * The origin of a migration trust anchor entry.
 *
 *   'baked' — from the build-time OFFICIAL_MIGRATION_ISSUERS constant. Authoritative; not removable.
 *   'parent-credential-chain' — from a verified AbaxxOne parent credential. NOT persisted.
 */
export type MigrationTrustAnchorSource = 'baked' | 'parent-credential-chain';

/**
 * A single migration trust anchor entry.
 *
 * `did` is the issuer DID that is trusted to sign migration credentials.
 * `source` distinguishes baked-at-build-time entries from runtime additions
 * via verified parent-credential-chain.
 */
export interface MigrationTrustAnchorEntry {
  readonly did: string;
  readonly source: MigrationTrustAnchorSource;
}

/**
 * Thrown by MigrationExecutor.execute() when the migration credential's issuer DID is
 * not in MigrationTrustAnchor's trusted set. Even if the signature verifies via
 * LocalTrustAnchorStore, the migration executor independently rejects unless the issuer
 * is a 'baked' or 'parent-credential-chain' source.
 */
export class UntrustedMigrationIssuerError extends Error {
  override readonly name = 'UntrustedMigrationIssuerError';
  constructor(public readonly issuerDid: string) {
    super(
      `Migration credential issuer ${issuerDid} is not trusted by MigrationTrustAnchor. ` +
        `Trusted sources are 'baked' (build-time OFFICIAL_MIGRATION_ISSUERS) and ` +
        `'parent-credential-chain' (verified parent instance credential). The runtime ` +
        `LocalTrustAnchorStore does NOT establish migration trust.`,
    );
  }
}

/**
 * Normalize a DID: strip the DID-URL fragment so `did:dht:abc#key-1` matches a bare-DID trust
 * entry. Rejects whitespace (logging-roundtrip artifacts that cause confusing lookup mismatches).
 *
 * @throws TypeError if `did` is not a non-empty string or contains whitespace.
 */
function normalizeMigrationDid(did: string, context: string): string {
  if (!did || typeof did !== 'string') {
    throw new TypeError(`${context}: did must be a non-empty string, got ${typeof did}`);
  }
  if (/\s/.test(did)) {
    throw new TypeError(`${context}: did must not contain whitespace; got ${JSON.stringify(did)}`);
  }
  // Per W3C DID Core §3.2.1, the fragment is part of the URL, not the identifier.
  const fragmentIdx = did.indexOf('#');
  return fragmentIdx === -1 ? did : did.slice(0, fragmentIdx);
}

// ─── JWT Issuer Decoding ─────────────────────────────────────────

/**
 * Decode the `iss` claim from a compact-JWS credential without verifying the signature.
 *
 * Caller is responsible for upstream cryptographic verification. Using the `iss` embedded in
 * the JWT (not a caller-supplied string) closes the wiring-bug surface where a caller could
 * pass a trusted issuer DID alongside an untrusted JWT.
 *
 * @throws TypeError if not compact-JWS, payload is not valid base64url JSON, or `iss` is missing.
 */
export function decodeJwtIssuer(jwt: string): string {
  if (!jwt || typeof jwt !== 'string') {
    throw new TypeError('credential JWT must be a non-empty string');
  }
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new TypeError(
      `credential JWT must be compact JWS (header.payload.signature); got ${parts.length} parts`,
    );
  }
  const payloadSegment = parts[1];
  if (!payloadSegment) {
    throw new TypeError('credential JWT payload segment is empty');
  }
  let payload: unknown;
  try {
    const json = Buffer.from(payloadSegment, 'base64url').toString('utf-8');
    payload = JSON.parse(json);
  } catch {
    throw new TypeError('credential JWT payload is not valid base64url JSON');
  }
  if (!payload || typeof payload !== 'object') {
    throw new TypeError('credential JWT payload is not a JSON object');
  }
  const iss = (payload as { iss?: unknown }).iss;
  if (typeof iss !== 'string' || !iss) {
    throw new TypeError('credential JWT is missing required iss claim');
  }
  return iss;
}

// ─── Branded Credential Types ─────────────────────────────────────

/**
 * A migration credential JWT whose issuer DID has been validated against MigrationTrustAnchor.
 * Branded for compile-time convenience only — brands are erased at runtime. MigrationExecutor
 * retains its own runtime trust check as defense-in-depth.
 */
export type TrustedMigrationCredential = string & {
  readonly __brand: 'TrustedMigrationCredential';
};

/**
 * A parent-instance credential JWT whose issuer DID has been validated against MigrationTrustAnchor.
 * Callers with a VerifiedParentCredential can extract the issuer DID and pass it to
 * `addFromParentCredentialChain()`.
 */
export type VerifiedParentCredential = string & { readonly __brand: 'VerifiedParentCredential' };

/**
 * Smart constructor for `TrustedMigrationCredential`.
 *
 * Extracts the issuer DID from the JWT payload's `iss` claim and checks it
 * against the provided trust anchor. Throws `UntrustedMigrationIssuerError`
 * if the issuer is not trusted.
 *
 * The caller is responsible for prior cryptographic signature verification
 * (e.g. via `VcVerifier`). This constructor only performs the trust-anchor
 * check — it does not re-verify the signature.
 *
 * @throws TypeError if the JWT is malformed or missing the `iss` claim.
 * @throws UntrustedMigrationIssuerError if the issuer is not in the trust anchor.
 */
export function asTrustedMigrationCredential(
  jwt: string,
  anchor: MigrationTrustAnchor,
): TrustedMigrationCredential {
  const issuerDid = decodeJwtIssuer(jwt);
  if (!anchor.isTrusted(issuerDid)) {
    throw new UntrustedMigrationIssuerError(issuerDid);
  }
  return jwt as TrustedMigrationCredential;
}

/**
 * Smart constructor for `VerifiedParentCredential`.
 *
 * Extracts the issuer DID from the JWT payload's `iss` claim and checks it
 * against the provided trust anchor. Throws `UntrustedMigrationIssuerError`
 * if the issuer is not trusted.
 *
 * The caller is responsible for prior cryptographic signature verification.
 * This constructor only performs the trust-anchor check.
 *
 * @throws TypeError if the JWT is malformed or missing the `iss` claim.
 * @throws UntrustedMigrationIssuerError if the issuer is not in the trust anchor.
 */
export function asVerifiedParentCredential(
  jwt: string,
  anchor: MigrationTrustAnchor,
): VerifiedParentCredential {
  const issuerDid = decodeJwtIssuer(jwt);
  if (!anchor.isTrusted(issuerDid)) {
    throw new UntrustedMigrationIssuerError(issuerDid);
  }
  return jwt as VerifiedParentCredential;
}

/**
 * MigrationTrustAnchor — the trust list MigrationExecutor consults before accepting a migration
 * credential. Seeds from OFFICIAL_MIGRATION_ISSUERS on construction ('baked'). Runtime additions
 * restricted to `addFromParentCredentialChain()` — no env, no constructor option, no admin API.
 *
 * Uses ECMAScript hard-private `#entries` — TypeScript `private` is type-erased; `#private` is
 * enforced by the JS engine so the trust list cannot be mutated from outside the class.
 */
export class MigrationTrustAnchor {
  readonly #entries: Map<string, MigrationTrustAnchorEntry>;

  constructor() {
    this.#entries = new Map();
    for (const did of OFFICIAL_MIGRATION_ISSUERS) {
      // Normalize even baked DIDs — defensive against mis-formatted entries in the constant.
      const normalized = normalizeMigrationDid(
        did,
        'MigrationTrustAnchor.OFFICIAL_MIGRATION_ISSUERS seed',
      );
      this.#entries.set(normalized, Object.freeze({ did: normalized, source: 'baked' as const }));
    }
  }

  /**
   * Add an issuer DID derived from a verified parent instance credential chain.
   *
   * The caller MUST have verified the parent credential before calling this
   * method. This class does not re-verify; it accepts the DID and records the
   * 'parent-credential-chain' source.
   *
   * The DID is normalized: fragment stripped, whitespace rejected. A baked
   * entry is never overwritten by a parent-credential-chain entry — re-adding
   * an existing DID is a no-op regardless of source.
   *
   * @throws TypeError if `did` is not a non-empty string or contains whitespace.
   */
  addFromParentCredentialChain(did: string): void {
    const normalized = normalizeMigrationDid(
      did,
      'MigrationTrustAnchor.addFromParentCredentialChain',
    );
    if (this.#entries.has(normalized)) {
      return;
    }
    this.#entries.set(
      normalized,
      Object.freeze({ did: normalized, source: 'parent-credential-chain' as const }),
    );
  }

  /**
   * Check whether a DID is trusted to sign migration credentials. O(1).
   *
   * Returns `false` for inputs that fail normalization rather than throwing —
   * this is on the hot path of MigrationExecutor.execute() and must not throw.
   */
  isTrusted(did: string): boolean {
    if (!did || typeof did !== 'string' || /\s/.test(did)) {
      return false;
    }
    const fragmentIdx = did.indexOf('#');
    const normalized = fragmentIdx === -1 ? did : did.slice(0, fragmentIdx);
    return this.#entries.has(normalized);
  }

  /**
   * Return all current entries as an array snapshot. Used for diagnostics
   * and audit-logging the migration trust topology.
   *
   * Returns a snapshot — callers must not mutate the returned array or its
   * elements. Each entry is already frozen.
   */
  list(): readonly MigrationTrustAnchorEntry[] {
    return Array.from(this.#entries.values());
  }
}
