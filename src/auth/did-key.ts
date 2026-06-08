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
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import type { AgentSigner } from '#types/auth.js';
import { createJwt } from '#crypto/jwt.js';
import { base58Encode } from '#crypto/base58.js';
import { REDACTED_SIGNER, withRedactedSerialization } from '#crypto/redact.js';

/** Generate a deterministic Ed25519 did:key from a 32-byte seed. Same seed = same DID. */
export function generateDidKeyFromSeed(seed: Buffer): {
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privKeyObj = createPrivateKey({
    key: Buffer.concat([pkcs8Header, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const pubKeyObj = createPublicKey(privKeyObj);

  const privDer = privKeyObj.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const pubDer = pubKeyObj.export({ type: 'spki', format: 'der' }) as Buffer;

  const rawPrivate = new Uint8Array(privDer.subarray(16));
  const rawPublic = new Uint8Array(pubDer.subarray(12));

  const multicodec = new Uint8Array(2 + rawPublic.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(rawPublic, 2);
  const did = `did:key:z${base58Encode(multicodec)}`;

  return { did, publicKey: rawPublic, privateKey: rawPrivate };
}

/** Generate a random Ed25519 key pair and return as a did:key DID. */
export function generateDidKey(): { did: string; publicKey: Uint8Array; privateKey: Uint8Array } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  const rawPublic = new Uint8Array(publicKey.subarray(12));
  const rawPrivate = new Uint8Array(privateKey.subarray(16));

  const multicodec = new Uint8Array(2 + rawPublic.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(rawPublic, 2);

  const did = `did:key:z${base58Encode(multicodec)}`;

  return { did, publicKey: rawPublic, privateKey: rawPrivate };
}

/** Create an opaque AgentSigner wrapping a private key. Raw key material is never exposed. */
export function createSigner(privateKey: Uint8Array): AgentSigner {
  const key = new Uint8Array(privateKey);
  const signer = withRedactedSerialization(
    {
      signJwt(payload: Record<string, unknown>): Promise<string> {
        return createJwt(payload, key);
      },
    },
    () => REDACTED_SIGNER,
  );
  return Object.freeze(signer);
}

/** Adapt an AgentSigner to the external Signer interface used by id-sdk and AbaxxOne APIs. */
export function toExternalSigner(
  agentSigner: AgentSigner,
  did: string,
): ((data: Uint8Array) => Promise<Uint8Array>) & { kid: string; algorithm: string } {
  const kid = `${did}#${did.split(':').pop()}`;

  const sign = async (data: Uint8Array): Promise<Uint8Array> => {
    const payload: Record<string, unknown> = {
      _raw: Buffer.from(data).toString('base64url'),
    };

    const jws = await agentSigner.signJwt(payload);

    const parts = jws.split('.');
    if (parts.length !== 3) {
      throw new Error(
        `[agents] toExternalSigner: unexpected JWS format — expected 3 parts, got ${parts.length}. ` +
          `This indicates a bug in createJwt() or a non-standard AgentSigner implementation.`,
      );
    }

    const signatureBytes = new Uint8Array(Buffer.from(parts[2], 'base64url'));
    return signatureBytes;
  };

  return Object.assign(sign, {
    kid,
    algorithm: 'EdDSA' as const,
  });
}
