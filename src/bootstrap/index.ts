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
 * Consumer-side env-var resolution helpers for the master key and trusted-server list.
 *
 * The library core never reads process.env directly — that's a consumer-boundary concern.
 * This subpath is the single sanctioned site for reading AGENTS_MASTER_KEY in first-party code.
 * `Buffer.from(hex, 'hex')` silently drops non-hex chars; this helper validates format first.
 */

import { MasterKeyMissingError } from '../errors/index.js';
import { asMasterKey, type MasterKey } from '../crypto/master-key.js';

/**
 * Hex-only pattern: exactly 64 characters from [0-9a-fA-F].
 * Rejects whitespace, padding characters, base64, and any UTF-8 variant.
 * This must match before Buffer.from to avoid silent truncation.
 */
const HEX_64_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Parse a hex-encoded master key into a branded 32-byte MasterKey.
 * Validates exactly 64 hex chars before decoding — closes the silent-truncation
 * footgun where Buffer.from(hex, 'hex') drops non-hex chars silently.
 *
 * @throws {Error} if hex is not exactly 64 hex characters.
 */
export function parseMasterKeyHex(hex: string): MasterKey {
  if (!HEX_64_RE.test(hex)) {
    throw new Error(
      'Master key must be exactly 64 hex characters (32 bytes). ' +
        `Got ${hex.length} character(s). ` +
        'Use lowercase or uppercase hex with no spaces, padding, or base64 encoding.',
    );
  }
  return asMasterKey(Buffer.from(hex, 'hex')); // asMasterKey re-validates length (defense in depth)
}

/**
 * Resolve the master encryption key from the `AGENTS_MASTER_KEY` environment
 * variable and return it as a 32-byte `Buffer`.
 *
 * Call this ONCE at application startup and thread the resulting `Buffer` into
 * `AgentScope.create(config, { masterKey })`. Do not call it inside hot paths.
 *
 * @throws {MasterKeyMissingError} — if `AGENTS_MASTER_KEY` is not set or is
 *   an empty string.
 * @throws {Error} — if `AGENTS_MASTER_KEY` is set but is not exactly 64 hex
 *   characters (e.g. wrong length, base64-encoded, contains whitespace or
 *   non-hex characters).
 *
 * @returns A 32-byte branded `MasterKey` ready to pass to `AgentScope.create()`.
 *   Since `MasterKey` IS a `Buffer` at runtime, external consumers that
 *   historically held the result as `Buffer` continue to work without code
 *   changes.
 *
 * @example
 * ```ts
 * import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
 *
 * // Call once at startup; throws early if env var is missing or malformed.
 * const masterKey = resolveMasterKeyFromEnv();
 * // Thread `masterKey` into AgentScope.create(config, { masterKey, ... }).
 * ```
 */
export function resolveMasterKeyFromEnv(): MasterKey {
  const hexKey = process.env.AGENTS_MASTER_KEY;

  if (!hexKey) {
    throw new MasterKeyMissingError();
  }

  return parseMasterKeyHex(hexKey);
}

/**
 * Parse trusted server DIDs from `AGENTS_TRUSTED_SERVERS` (comma-separated).
 * Returns [] if unset. Trims entries, drops empties, deduplicates.
 * No DID format validation — format-agnostic to avoid coupling to a specific allowlist.
 *
 * @example
 * ```ts
 * const store = new LocalTrustAnchorStore({
 *   ownServerDid: serverIdentity.did,
 *   keystore,
 *   initialTrustedServers: resolveTrustedServersFromEnv(),
 * });
 * ```
 */
export function resolveTrustedServersFromEnv(): string[] {
  const raw = process.env.AGENTS_TRUSTED_SERVERS;
  if (!raw) return [];

  const seen = new Set<string>();
  const result: string[] = [];
  for (const part of raw.split(',')) {
    const did = part.trim();
    if (!did) continue;
    if (seen.has(did)) continue;
    seen.add(did);
    result.push(did);
  }
  return result;
}
