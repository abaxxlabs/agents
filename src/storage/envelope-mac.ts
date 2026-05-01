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
// canonicalize ships as CJS with `module.exports = function serialize(...)` and
// a hand-rolled .d.ts declaring `export default function serialize(...)`. Under
// Node16/NodeNext moduleResolution in TS, the default-import form is typed as
// the module namespace and is reported as "not callable" even though it
// functions correctly at runtime. The `* as` + `.default` form works across
// both TS typecheck and Node runtime CJS-ESM interop.
import * as canonicalizeModule from 'canonicalize';
const canonicalize = (
  canonicalizeModule as unknown as {
    default: (input: unknown) => string | undefined;
  }
).default;
import type { SessionEnvelope } from './types.js';
import { EnvelopeTooLargeError } from './types.js';
import type { MasterKey } from '../crypto/master-key.js';

// ─── Public constants ───────────────────────────────────────────────────────────

/**
 * HKDF "info" context for the session MAC key. Each subsystem MUST use a
 * distinct context string. Changing this invalidates all envelopes in flight.
 */
export const HKDF_CONTEXT_SESSION_MAC = 'agents:SessionStore:mac:v1';

/** Zero-length HKDF salt: master key provides entropy; per-deployment salt would break cross-process agreement. */
export const HKDF_SALT_SESSION_MAC = Buffer.alloc(0);

/**
 * Max canonical envelope size (bytes). Checked AFTER canonicalization.
 * Caps unbounded oidcGroupClaims; typical envelope is < 2KB.
 */
export const MAX_ENVELOPE_BYTES = 32768;

/**
 * MAC byte length for HMAC-SHA256. Exported so adapters can size their BLOB
 * columns consistently.
 */
export const MAC_BYTES = 32;

// ─── Key derivation ─────────────────────────────────────────────────────────────

/**
 * Derive the MAC key from a master key via HKDF-SHA256.
 *
 * Called once at startup by adapters. The derived key is held in-memory for
 * the process lifetime and used for every MAC compute/verify. HKDF is
 * deterministic, so all instances sharing the same master key derive the
 * same MAC key — required for cross-instance MAC verification.
 *
 * @param masterKey The library master key (32 bytes, branded `MasterKey`).
 *   Construct via `asMasterKey(buf)` from a trusted source. The brand prevents
 *   accidental flow into loggers or error formatters at compile time.
 * @returns A 32-byte Buffer suitable for HMAC-SHA256.
 */
export function deriveSessionMacKey(masterKey: MasterKey): Buffer {
  // hkdfSync returns an ArrayBuffer; wrap in Buffer for Node API compat.
  const derived = hkdfSync(
    'sha256',
    masterKey,
    HKDF_SALT_SESSION_MAC,
    HKDF_CONTEXT_SESSION_MAC,
    32,
  );
  return Buffer.from(derived);
}

// ─── Canonical encoding ─────────────────────────────────────────────────────────

/**
 * Canonicalize a SessionEnvelope to its RFC 8785 (JCS) byte encoding.
 *
 * Exposed for tests. Adapters typically call `computeMac()` which composes
 * canonicalize + size-check + HMAC in one step.
 */
export function canonicalizeEnvelope(envelope: SessionEnvelope): Buffer {
  // canonicalize returns a UTF-8 string. RFC 8785 byte encoding is the UTF-8
  // representation, so Buffer.from(canonical, 'utf8') is correct.
  //
  // canonicalize() may return undefined for non-JSON values. Since
  // SessionEnvelope is a plain-object shape, this should never happen in
  // practice — treat it as a programmer error rather than a silent
  // zero-length buffer.
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

// ─── MAC compute / verify ───────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 over the canonical-encoded envelope.
 *
 * Also enforces the size cap. put() flow:
 *   1. canonicalize
 *   2. size-check (throws EnvelopeTooLargeError if > MAX_ENVELOPE_BYTES)
 *   3. HMAC-SHA256
 *   4. return { mac, canonicalBytes } — caller writes both to the store
 *
 * Size check is AFTER canonicalization because canonical output length is
 * the authoritative measure.
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
 * Verify a stored envelope against its stored MAC.
 *
 * Returns true on match, false on mismatch. Does NOT throw on mismatch — the
 * caller decides whether to throw EnvelopeIntegrityError or handle the
 * mismatch differently.
 *
 * Uses `timingSafeEqual` to prevent timing-oracle attacks that leak byte-by-
 * byte MAC comparison progress. For HMAC this matters less than for password
 * comparisons, but the cost is nil.
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
