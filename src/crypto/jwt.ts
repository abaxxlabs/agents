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

import {
  SignJWT,
  compactVerify,
  decodeJwt as joseDecodeJwt,
  decodeProtectedHeader,
  importJWK,
  errors as joseErrors,
} from 'jose';
import { ed25519 } from '@noble/curves/ed25519';
import { createHash } from 'node:crypto';
import { CredentialMalformedError } from '#errors/index.js';
import type { CredentialScope } from '#types/credential.js';

type ImportedKey = Awaited<ReturnType<typeof importJWK>>;
type ImportJwkFn = typeof importJWK;

const KEY_CACHE_CAP = 256;

const privateKeyCache = new Map<string, ImportedKey>();
const publicKeyCache = new Map<string, ImportedKey>();
let importJwkForKey: ImportJwkFn = importJWK;

export function clearJwtKeyCachesForTest(): void {
  privateKeyCache.clear();
  publicKeyCache.clear();
}

export function setJwtImportJwkForTest(fn?: ImportJwkFn): void {
  importJwkForKey = fn ?? importJWK;
  clearJwtKeyCachesForTest();
}

function lruGet(cache: Map<string, ImportedKey>, key: string): ImportedKey | undefined {
  const value = cache.get(key);
  if (value === undefined) return undefined;
  cache.delete(key);
  cache.set(key, value);
  return value;
}

function lruSet(cache: Map<string, ImportedKey>, key: string, value: ImportedKey): void {
  if (cache.has(key)) cache.delete(key);
  cache.set(key, value);
  if (cache.size > KEY_CACHE_CAP) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey !== undefined) cache.delete(oldestKey);
  }
}

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  jti?: string;
  iat?: number;
  nbf?: number;
  exp?: number;
  maxDepth?: number;
  vc?: {
    '@context'?: string[];
    type?: string[];
    credentialSubject?: {
      id?: string;
      scope?: CredentialScope;
      owner?: string;
      [key: string]: unknown;
    };
    credentialStatus?: {
      id?: string;
      type?: string;
      statusPurpose?: string;
      statusListIndex?: string;
      statusListCredential?: string;
    };
  };
  [key: string]: unknown;
}

/**
 * Decode a JWT into its constituent parts without verifying the signature.
 *
 * @param jwt - Compact JWS string (header.payload.signature).
 * @returns Decoded header and payload.
 * @throws {CredentialMalformedError} if the JWT is malformed.
 */
export function decodeJwt(jwt: string): {
  header: JwtHeader;
  payload: JwtPayload;
} {
  try {
    const payload = joseDecodeJwt(jwt) as JwtPayload;
    const header = decodeProtectedHeader(jwt) as JwtHeader;
    return { header, payload };
  } catch {
    throw new CredentialMalformedError('Malformed JWT');
  }
}

/**
 * Create a signed JWT using an Ed25519 private key.
 *
 * @param payload - JWT claims to encode.
 * @param privateKey - Raw 32-byte Ed25519 private key.
 * @returns Compact JWS string.
 */
export async function createJwt(payload: JwtPayload, privateKey: Uint8Array): Promise<string> {
  const cacheKey = createHash('sha256').update(privateKey).digest('base64url');
  let key = lruGet(privateKeyCache, cacheKey);
  if (key === undefined) {
    const publicKey = ed25519.getPublicKey(privateKey);
    key = await importJwkForKey(
      {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(publicKey).toString('base64url'),
        d: Buffer.from(privateKey).toString('base64url'),
      },
      'EdDSA',
    );
    lruSet(privateKeyCache, cacheKey, key);
  }
  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .sign(key);
}

/**
 * Verify an Ed25519 JWT signature against a public key.
 * This does not validate claims, credential policy, expiry, issuer, audience, or revocation.
 *
 * @param jwt - Compact JWS string.
 * @param publicKey - Raw 32-byte Ed25519 public key.
 * @returns `true` if the signature is valid.
 */
export async function verifyJwtSignature(jwt: string, publicKey: Uint8Array): Promise<boolean> {
  const cacheKey = Buffer.from(publicKey).toString('base64url');
  const cachedKey = lruGet(publicKeyCache, cacheKey);
  const key =
    cachedKey ??
    (await importJwkForKey(
      {
        kty: 'OKP',
        crv: 'Ed25519',
        x: cacheKey,
      },
      'EdDSA',
    ));
  try {
    await compactVerify(jwt, key, { algorithms: ['EdDSA'] });
    if (cachedKey === undefined) lruSet(publicKeyCache, cacheKey, key);
    return true;
  } catch (err) {
    if (
      err instanceof joseErrors.JWSSignatureVerificationFailed ||
      err instanceof joseErrors.JWSInvalid ||
      err instanceof joseErrors.JOSEAlgNotAllowed ||
      err instanceof joseErrors.JOSENotSupported
    )
      return false;
    throw err;
  }
}
