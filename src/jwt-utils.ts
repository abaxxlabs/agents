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

import { SignJWT, compactVerify, decodeJwt as joseDecodeJwt, decodeProtectedHeader, importJWK, errors as joseErrors } from 'jose';
import { ed25519 } from '@noble/curves/ed25519';
import { CredentialMalformedError } from './errors.js';
import type { CredentialScope } from './types.js';

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
  const publicKey = ed25519.getPublicKey(privateKey);
  const key = await importJWK(
    {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey).toString('base64url'),
      d: Buffer.from(privateKey).toString('base64url'),
    },
    'EdDSA',
  );
  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .sign(key);
}

/**
 * Verify an Ed25519 JWT signature against a public key.
 *
 * @param jwt - Compact JWS string.
 * @param publicKey - Raw 32-byte Ed25519 public key.
 * @returns `true` if the signature is valid.
 */
export async function verifyJwtSignature(jwt: string, publicKey: Uint8Array): Promise<boolean> {
  const key = await importJWK(
    {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey).toString('base64url'),
    },
    'EdDSA',
  );
  try {
    await compactVerify(jwt, key, { algorithms: ['EdDSA'] });
    return true;
  } catch (err) {
    if (
      err instanceof joseErrors.JWSSignatureVerificationFailed ||
      err instanceof joseErrors.JWSInvalid ||
      err instanceof joseErrors.JOSEAlgNotAllowed ||
      err instanceof joseErrors.JOSENotSupported
    ) return false;
    throw err;
  }
}
