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
 * ServerIdentity — the server's own DID and signing key.
 *
 * Persisted in the keystore so it survives process restarts — a new DID on every restart
 * would invalidate all previously-issued binding credentials.
 *
 * Key lifecycle: generate on first run, load on subsequent runs, explicit rotation via
 * `rotateServerIdentity()`. Rotation invalidates all existing binding VCs; operators must
 * re-issue. Private key is stored in the keystore only — never in env vars or config files.
 */

import { createPrivateKey, createPublicKey } from 'node:crypto';
import type { KeystoreBackend } from './keystore.js';
import type { AgentSigner } from '../types.js';
import { generateDidKey, createSigner } from '../auth/agent.js';
import { VcVerifier } from '../vc-verifier.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Keystore keys for the server identity.
 * Prefixed with 'agents:server:' to avoid collisions with other keystore entries.
 */
const KEYSTORE_DID = 'agents:server:did';
const KEYSTORE_PRIVATE_KEY = 'agents:server:private-key-hex';

// ─── Public Interface ─────────────────────────────────────────────────────────

/**
 * The server's own DID and signing capability.
 *
 * ServerIdentity is the issuer of IdentityBindingCredentials.
 * It does not hold a reference to the raw private key after construction —
 * only the opaque AgentSigner is accessible.
 */
export interface ServerIdentity {
  /** The server's Ed25519 DID (did:key: format). Stable across restarts. */
  did: string;
  /**
   * Opaque signer — wraps the private key in a closure.
   * Only exposes signJwt(). Key material is never accessible from outside.
   */
  signer: AgentSigner;
  /**
   * Raw public key bytes (32-byte Ed25519).
   * Safe to share — used by VcVerifier for offline verification.
   */
  publicKey: Uint8Array;
  /**
   * Whether this is a freshly generated identity (first run) or a loaded one.
   * Informational — callers can log "new server identity created" vs "loaded".
   */
  isNew: boolean;
}

// ─── Initialization ───────────────────────────────────────────────────────────

/**
 * Initialize the server's DID and signing key.
 *
 * First run: generates a fresh Ed25519 keypair and persists it.
 * Subsequent runs: loads the existing identity from the keystore.
 *
 * The verifier parameter is optional but should be provided in production —
 * it registers the public key for local verification. Without registration,
 * callers must resolve the server's DID via JWKS on every verification,
 * adding latency and an external dependency.
 *
 * @param keystore   KeystoreBackend to persist and retrieve the identity.
 * @param verifier   Optional VcVerifier — registers public key for local resolution.
 */
export async function initializeServerIdentity(
  keystore: KeystoreBackend,
  verifier?: VcVerifier,
): Promise<ServerIdentity> {
  // Parallel reads — on macOS keychain each is a subprocess; sequential adds ~20ms.
  const [existingDid, existingKeyHex] = await Promise.all([
    keystore.read(KEYSTORE_DID),
    keystore.read(KEYSTORE_PRIVATE_KEY),
  ]);

  if (existingDid && existingKeyHex) {
    // Load existing identity — reconstruct from stored key material
    return loadServerIdentity(existingDid, existingKeyHex, verifier);
  }

  // First run — generate a new identity and persist it
  return generateServerIdentity(keystore, verifier);
}

/**
 * Rotate the server's DID and signing key.
 *
 * Generates a new keypair, overwrites the keystore entry, returns the new identity.
 * WARNING: invalidates all binding credentials issued by the previous DID.
 * Operators must re-issue bindings for all agents after rotation.
 *
 * Call this when:
 * - A private key compromise is suspected
 * - Org-wide credential invalidation is desired
 *
 * Not called automatically — rotation is always an explicit operator action.
 *
 * @param keystore   KeystoreBackend to persist the new identity.
 * @param verifier   Optional VcVerifier — registers the new public key.
 */
export async function rotateServerIdentity(
  keystore: KeystoreBackend,
  verifier?: VcVerifier,
): Promise<ServerIdentity> {
  return generateServerIdentity(keystore, verifier);
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Generate and persist a new server identity.
 * Called on first run and on explicit rotation.
 */
async function generateServerIdentity(
  keystore: KeystoreBackend,
  verifier?: VcVerifier,
): Promise<ServerIdentity> {
  const { did, publicKey, privateKey } = generateDidKey();

  // Persist before returning — keys that won't survive restart are worse than no keys.
  await keystore.write(KEYSTORE_DID, did);
  await keystore.write(KEYSTORE_PRIVATE_KEY, Buffer.from(privateKey).toString('hex'));

  const signer = createSigner(privateKey);

  if (verifier) {
    verifier.registerKey(did, publicKey);
  }

  return { did, signer, publicKey, isNew: true };
}

/**
 * Load a server identity from stored key material.
 * Reconstructs the Ed25519 public key from the stored DID.
 */
function loadServerIdentity(
  did: string,
  privateKeyHex: string,
  verifier?: VcVerifier,
): ServerIdentity {
  const privateKeyBytes = new Uint8Array(Buffer.from(privateKeyHex, 'hex'));

  // Reconstruct the public key from private key bytes — avoids storing the public key separately.
  // PKCS8 prefix (302e020100300506032b657004220420) wraps the 32-byte Ed25519 seed.
  const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const pkcs8Der = Buffer.concat([pkcs8Header, Buffer.from(privateKeyBytes)]);
  const privKeyObj = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const pubKeyObj = createPublicKey(privKeyObj);
  const pubKeyDer = pubKeyObj.export({ type: 'spki', format: 'der' }) as Buffer;
  const publicKey = new Uint8Array(pubKeyDer.subarray(12)); // Ed25519 SPKI: 12-byte prefix + 32-byte key

  const signer = createSigner(privateKeyBytes);

  if (verifier) {
    verifier.registerKey(did, publicKey);
  }

  return { did, signer, publicKey, isNew: false };
}
