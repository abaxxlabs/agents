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
 * Shared OIDC discovery utilities.
 *
 * validateDiscoveredEndpoint() and parseCacheControlMaxAge() are consumed by
 * both GenericOidcProvider and AbaxxOneOidcProvider. Single source of truth
 * for SSRF and cache-control parsing across provider implementations.
 */

import { AuthUnavailableError, DiscoveryEndpointBlockedError } from '../errors.js';
import type { Logger } from '../logger.js';
import { defaultLogger } from '../logger.js';

export const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Minimum discovery cache TTL (milliseconds). Prevents a compromised or
 * misconfigured provider from forcing near-continuous re-fetching via
 * Cache-Control: max-age=1, which would amplify SSRF exposure and create
 * a DoS vector against the discovery endpoint.
 * 30 seconds: low enough to detect key rotations quickly, high enough to
 * prevent fetch-loop abuse.
 */
export const MIN_DISCOVERY_TTL_MS = 30 * 1000; // 30 seconds

/**
 * Validate that a discovered endpoint URL is safe to use.
 *
 * Endpoints from OIDC discovery documents must be HTTPS to prevent credential
 * leakage over plaintext connections.
 *
 * Cross-origin endpoints (e.g. Google's oauth2.googleapis.com token endpoint
 * vs. accounts.google.com issuer) are only accepted when the endpoint host
 * appears in the caller's `allowedCrossOriginHosts`. A compromised discovery
 * document could redirect token exchange to an attacker-controlled HTTPS host;
 * the per-issuer allowlist prevents this by rejecting unlisted hosts before
 * any network exchange occurs.
 *
 * Localhost HTTP is permitted only when NODE_ENV is `development` or `test` —
 * this is a runtime-shape gate (not posture configuration) and is one of the
 * very few places the library reads `process.env` directly.
 *
 * @param endpoint     The endpoint URL from the discovery document.
 * @param field        Field name for error messages (e.g. 'token_endpoint').
 * @param issuerOrigin The issuer's origin for cross-origin comparison.
 * @param providerLabel Label for log messages (e.g. 'Generic OIDC', 'AbaxxOne').
 * @param allowedCrossOriginHosts Hostnames permitted to differ from the issuer
 *   origin. If undefined and a cross-origin endpoint is encountered, throws
 *   `DiscoveryEndpointBlockedError` with `configMissing: true`.
 */
export function validateDiscoveredEndpoint(
  endpoint: string,
  field: string,
  issuerOrigin: string,
  providerLabel = 'OIDC',
  allowedCrossOriginHosts?: readonly string[],
  logger?: Logger,
): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new AuthUnavailableError(`Discovery document has invalid URL for ${field}: ${endpoint}`);
  }

  const env = (process.env.NODE_ENV ?? '').toLowerCase();
  const isDev = env === 'development' || env === 'test';
  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(isLocalhost && isDev)) {
    throw new AuthUnavailableError(
      `Discovery document ${field} is not HTTPS: ${endpoint} — refusing to send credentials over plaintext` +
        (isLocalhost ? '. Set NODE_ENV=development to allow localhost HTTP.' : ''),
    );
  }

  if (url.origin !== issuerOrigin && !isLocalhost) {
    if (!allowedCrossOriginHosts) {
      throw new DiscoveryEndpointBlockedError(
        field, url.hostname, issuerOrigin, true, providerLabel,
      );
    }
    if (!allowedCrossOriginHosts.includes(url.hostname)) {
      throw new DiscoveryEndpointBlockedError(
        field, url.hostname, issuerOrigin, false, providerLabel,
      );
    }
  }
}

/**
 * Extract max-age value (seconds) from a Cache-Control header.
 * Returns undefined if the header is absent, unparseable, or contains no max-age.
 */
export function parseCacheControlMaxAge(header: string | null): number | undefined {
  if (!header) return undefined;
  const match = header.match(/max-age\s*=\s*(\d+)/);
  if (!match) return undefined;
  const seconds = parseInt(match[1], 10);
  return Number.isFinite(seconds) && seconds > 0 ? seconds : undefined;
}
