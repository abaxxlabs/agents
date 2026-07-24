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

/** Shared OIDC discovery utilities for SSRF validation and cache-control parsing. */

import { AuthUnavailableError, DiscoveryEndpointBlockedError } from '#errors/index.js';

export const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1000; // 1 hour

/** Floor on discovery TTL to prevent fetch-loop abuse from low max-age values. */
export const MIN_DISCOVERY_TTL_MS = 30 * 1000; // 30 seconds

/**
 * Validate a discovered endpoint URL: must be HTTPS (localhost HTTP allowed in dev/test),
 * and cross-origin hosts must appear in `allowedCrossOriginHosts` to prevent SSRF via
 * compromised discovery documents. Note: localhost HTTP check reads NODE_ENV (policy exception).
 */
export function validateDiscoveredEndpoint(
  endpoint: string,
  field: string,
  issuerOrigin: string,
  providerLabel = 'OIDC',
  allowedCrossOriginHosts?: readonly string[],
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

/** Extract max-age (seconds) from a Cache-Control header. */
export function parseCacheControlMaxAge(header: string | null): number | undefined {
  if (!header) return undefined;
  const match = header.match(/max-age\s*=\s*(\d+)/);
  if (!match) return undefined;
  const seconds = parseInt(match[1], 10);
  return Number.isFinite(seconds) && seconds > 0 ? seconds : undefined;
}
