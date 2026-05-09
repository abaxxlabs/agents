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

import { sign as ed25519Sign, verify as ed25519Verify } from 'node:crypto';
import { CredentialMalformedError } from './errors.js';
import type { CredentialScope } from './types.js';

export function base64UrlDecode(str: string): Buffer {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

export function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
 * @returns Decoded header, payload, raw signature bytes, and the signing input.
 * @throws {CredentialMalformedError} if the JWT does not have exactly 3 parts.
 */
export function decodeJwt(jwt: string): {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Buffer;
  signingInput: string;
} {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new CredentialMalformedError('JWT must have 3 parts (header.payload.signature)');
  }

  const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf-8')) as JwtHeader;
  const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf-8')) as JwtPayload;
  const signature = base64UrlDecode(parts[2]);
  const signingInput = `${parts[0]}.${parts[1]}`;

  return { header, payload, signature, signingInput };
}

/**
 * Create a signed JWT using an Ed25519 private key.
 *
 * @param payload - JWT claims to encode.
 * @param privateKey - Raw 32-byte Ed25519 private key.
 * @returns Compact JWS string.
 */
export function createJwt(payload: JwtPayload, privateKey: Uint8Array): string {
  const header: JwtHeader = { alg: 'EdDSA', typ: 'JWT' };
  const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const keyObj = {
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(privateKey),
    ]),
    format: 'der' as const,
    type: 'pkcs8' as const,
  };

  const sig = ed25519Sign(undefined, Buffer.from(signingInput), keyObj);
  const sigB64 = base64UrlEncode(sig);

  return `${signingInput}.${sigB64}`;
}

/**
 * Verify an Ed25519 JWT signature against a public key.
 *
 * @param jwt - Compact JWS string.
 * @param publicKey - Raw 32-byte Ed25519 public key.
 * @returns `true` if the signature is valid.
 */
export function verifyJwtSignature(jwt: string, publicKey: Uint8Array): boolean {
  const { signingInput, signature } = decodeJwt(jwt);

  const keyObj = {
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey)]),
    format: 'der' as const,
    type: 'spki' as const,
  };

  return ed25519Verify(undefined, Buffer.from(signingInput), keyObj, signature);
}
