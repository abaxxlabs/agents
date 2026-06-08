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
 * Verifiable Presentation (VP) creation (W3C VC Data Model §4.10).
 *
 * Key architectural distinction:
 *   VCs are REUSABLE — like a driver's license, valid until expiry.
 *   VPs are SINGLE-USE — each presentation gets a fresh nonce (JTI) and may be audience-bound.
 *   The credential already exists and can be replayed to other servers; replay protection
 *   belongs at the VP layer, not the VC layer.
 *
 * Replay protection tracks VP nonces — a VC can be presented many times (each in a fresh VP),
 * but the same VP cannot be replayed. ScopeEngine wraps raw VCs in VPs before verification.
 */

import type { AgentSigner } from '#types/index.js';
import { parseDuration } from '#config.js';
import { generateUuid7 } from './uuid7.js';

/**
 * VP type constant — used by VcVerifier to distinguish VPs from VCs.
 * A JWT with this value in payload.vp.type is treated as a presentation.
 */
export const VP_TYPE = 'VerifiablePresentation';

// 60s default: the VP lifetime IS the first-mover replay window for a captured presentation.
// The seenJtis cache only catches the second redeem. Longer windows are opt-in via the `lifetime` option.
const DEFAULT_VP_LIFETIME = '60s';

export interface CreatePresentationOptions {
  /**
   * The verifier DID(s) this VP is addressed to. Becomes the `aud` claim.
   *
   * Pass a single DID string for point-to-point presentation. Pass an array for
   * multi-verifier scenarios (multi-region setup, primary + failover, broadcast).
   * The verifier accepts the VP if its `expectedAudience` appears anywhere in the
   * array. Per RFC 7519 §4.1.3, `aud` MAY be either a string or an array of
   * case-sensitive strings — both shapes are handled by `VcVerifier` already.
   */
  audience?: string | string[];
  /** Override the VP's JTI. Defaults to a fresh UUIDv4. */
  nonce?: string;
  /**
   * VP lifetime as a duration string. Defaults to `'60s'`.
   *
   * Accepted format: integer + unit, where unit is one of `s` (seconds),
   * `m` (minutes), `h` (hours), or `d` (days). Examples: `'30s'`, `'5m'`,
   * `'1h'`, `'1d'`. Compound (`'1m30s'`) and fractional (`'1.5s'`) forms are
   * not accepted — pass the equivalent integer in a smaller unit instead.
   * Minimum: 1 second. `'0s'` and other zero values throw.
   *
   * Practical maximum: 1 day. The library does not enforce an upper bound
   * (consistent with `resolverCacheTtl`), but lifetimes longer than ~24h
   * defeat the "VP is a single-use envelope" model — issue a longer-lived VC
   * instead and re-present it with fresh, short VPs.
   *
   * Tighter is better: the VP's `exp` defines the first-mover replay window for
   * a captured presentation. Verifier-side `clockSkew` (default 5s, ceiling 30s)
   * extends the effective accept window by that amount past `exp`. For agent-to-agent
   * RPC, 30–60s is typically sufficient. For human-in-the-loop flows where a
   * presentation may sit in a UI before being redeemed, pass a longer value
   * explicitly (e.g. `'5m'`) — the prior default.
   */
  lifetime?: string;
}

/**
 * Wrap a Verifiable Credential JWT in a Verifiable Presentation.
 *
 * The VP is signed by the agent's private key (via AgentSigner), proving
 * that the presenter is the credential holder — not just someone who
 * intercepted the VC JWT. The fresh JTI on every call is what enables
 * per-presentation replay protection without making the VC single-use.
 *
 * @param vcJwt      The raw VC JWT to present.
 * @param agentDid   The DID of the agent creating the presentation.
 * @param signer     The agent's opaque signing handle.
 * @param options    Optional audience binding, nonce override, and lifetime.
 * @returns          A signed VP JWT (compact JWS) containing the VC.
 */
export async function createPresentation(
  vcJwt: string,
  agentDid: string,
  signer: AgentSigner,
  options: CreatePresentationOptions = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const nonce = options.nonce || generateUuid7();
  // parseDuration throws on malformed input — surfaces misconfiguration at call time.
  const lifetimeSeconds = Math.floor(parseDuration(options.lifetime ?? DEFAULT_VP_LIFETIME) / 1000);
  // Floor at 1s: parseDuration accepts '0s'/'0m' which would produce exp = now (born-expired).
  if (lifetimeSeconds < 1) {
    throw new Error(
      `VP lifetime must be at least 1 second, got '${options.lifetime}' (= ${lifetimeSeconds}s). ` +
        `Pass a positive duration like '30s' or '5m'.`,
    );
  }

  const payload: Record<string, unknown> = {
    iss: agentDid,
    jti: nonce,
    iat: now,
    exp: now + lifetimeSeconds,
    vp: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [VP_TYPE],
      verifiableCredential: [vcJwt],
    },
  };

  if (options.audience) {
    payload.aud = options.audience;
  }

  return await signer.signJwt(payload);
}
