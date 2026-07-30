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
 * HMAC-SHA256 integrity for SessionStore envelopes (RFC 8785 canonical JSON).
 *
 * Identity fields (humanDid, oidcSubject, oidcIssuer) cannot be re-derived —
 * they're key-equivalent material. MAC is the only defense against row tampering.
 *
 * MAC key is HKDF-derived from the master key with a distinct context string.
 * `canonicalize` is exact-pinned (no caret) — a silent version bump that changes
 * number formatting would invalidate every envelope in flight.
 */

import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
// This import shape satisfies both canonicalize's CJS runtime and its default-export types.
import * as canonicalizeModule from 'canonicalize';
const canonicalize = (
  canonicalizeModule as unknown as {
    default: (input: unknown) => string | undefined;
  }
).default;
import type { SessionEnvelope } from './types.js';
import { EnvelopeTooLargeError } from './types.js';
import type { MasterKey } from '#crypto/master-key.js';

/**
 * HKDF context isolated to session MACs. Changing it invalidates persisted envelopes.
 */
export const HKDF_CONTEXT_SESSION_MAC = 'agents:SessionStore:mac:v1';

/** A deployment salt would prevent instances from deriving the same MAC key. */
export const HKDF_SALT_SESSION_MAC = Buffer.alloc(0);

/** Maximum canonical envelope size, bounding untrusted OIDC group claims. */
export const MAX_ENVELOPE_BYTES = 32768;

/** HMAC-SHA256 byte length exposed for adapter column sizing. */
export const MAC_BYTES = 32;

/**
 * Derives the shared session MAC key via HKDF-SHA256.
 * @param masterKey The branded 32-byte library master key.
 * @returns A 32-byte Buffer suitable for HMAC-SHA256.
 */
export function deriveSessionMacKey(masterKey: MasterKey): Buffer {
  const derived = hkdfSync(
    'sha256',
    masterKey,
    HKDF_SALT_SESSION_MAC,
    HKDF_CONTEXT_SESSION_MAC,
    32,
  );
  return Buffer.from(derived);
}

/** Canonicalizes a SessionEnvelope to RFC 8785 UTF-8 bytes. */
export function canonicalizeEnvelope(envelope: SessionEnvelope): Buffer {
  const canonical = canonicalize(envelope as unknown as Record<string, unknown>);
  if (canonical === undefined) {
    throw new Error(
      '[envelope-mac] canonicalize() returned undefined — envelope contains ' +
        'non-JSON values (e.g., functions, symbols). This is a programmer error; ' +
        'SessionEnvelope should contain only JSON-serializable fields.',
    );
  }
  return Buffer.from(canonical, 'utf8');
}

/**
 * Computes HMAC-SHA256 and enforces the canonical byte-size limit.
 * @throws {EnvelopeTooLargeError} When canonical data exceeds the size limit.
 */
export function computeMac(
  envelope: SessionEnvelope,
  macKey: Buffer,
): { mac: Buffer; canonicalBytes: Buffer } {
  const canonicalBytes = canonicalizeEnvelope(envelope);
  if (canonicalBytes.length > MAX_ENVELOPE_BYTES) {
    throw new EnvelopeTooLargeError(canonicalBytes.length, MAX_ENVELOPE_BYTES);
  }
  const mac = createHmac('sha256', macKey).update(canonicalBytes).digest();
  return { mac, canonicalBytes };
}

/**
 * Verifies a stored envelope using a constant-time MAC comparison.
 * @returns False on mismatch; callers decide how to surface tampering.
 */
export function verifyMac(
  envelope: SessionEnvelope,
  storedMac: Buffer | Uint8Array,
  macKey: Buffer,
): boolean {
  const expected = createHmac('sha256', macKey).update(canonicalizeEnvelope(envelope)).digest();
  const provided = Buffer.isBuffer(storedMac) ? storedMac : Buffer.from(storedMac);
  if (expected.length !== provided.length) return false;
  return timingSafeEqual(expected, provided);
}
