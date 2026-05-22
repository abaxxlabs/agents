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

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import type { AuthenticatedSession } from '../types/auth.js';
import type { IssueCredentialOptions } from '../types/credential.js';
import { VcVerifier } from '../vc-verifier.js';
import {
  assertScopeFitsInCeiling,
  unrestrictedCeiling,
  type ScopeCeiling,
} from './ceiling.js';
import {
  ParentCredentialRequestFailedError,
} from '../errors/index.js';
import type { IdSdkInstance } from '../types/id-sdk.js';
import {
  issueCredential,
  issueCredentialWithSdk,
  issueCredentialFromParent,
} from './credential-issuance.js';
import { generateDidKeyFromSeed } from './did-key.js';
import { base58Encode } from '../crypto/base58.js';
import type { Logger } from '../logger.js';
import { getLogger } from '../logger.js';
import { assertExpiresInBound } from '../config.js';

function revokeCredentialHelper(
  verifier: VcVerifier,
  sdk: IdSdkInstance | undefined,
  context?: string,
  logger: Logger = getLogger(),
): (credentialId: string) => Promise<{ sdkNotificationFailed?: Error }> {
  return async (credentialId: string) => {
    await verifier.revokeAsync(credentialId);

    if (sdk) {
      try {
        await sdk.vc.revokeCredential({ credentialId });
      } catch (err) {
        const sdkErr = err instanceof Error ? err : new Error(String(err));
        const label = context ? ` ${context}` : '';
        logger.warn(
          `[agents] SDK revokeCredential notification failed${label} for ${credentialId}: ${sdkErr.message}`,
          { credentialId, error: sdkErr.message },
        );
        return { sdkNotificationFailed: sdkErr };
      }
    }
    return {};
  };
}

/** Build an AuthenticatedSession for a known human DID. */
export function createSessionFromDid(
  humanDid: string,
  email: string | undefined,
  verifier: VcVerifier,
  sdk?: IdSdkInstance,
  _oidcConfig?: { tenantUrl: string },
  humanPrivateKey?: Uint8Array,
  ceiling: ScopeCeiling = unrestrictedCeiling(),
  parentConfig?: {
    provider: {
      requestAgentCredential: (
        accessToken: string,
        agentDid: string,
        options: { columns: string[]; actions: string[]; expiresIn: string | number; maxDepth?: number },
      ) => Promise<{ jwt: string; issuerDid: string }>;
    };
    accessToken: string;
    issuerDid: string;
    credentialExp: number;
  },
  logger: Logger = getLogger(),
): AuthenticatedSession {
  return {
    humanDid,
    email,
    scopeCeiling: ceiling,
    parentIssuerDid: parentConfig?.issuerDid,
    parentCredentialExp: parentConfig?.credentialExp,

    async issueCredential(options: IssueCredentialOptions): Promise<string> {
      assertScopeFitsInCeiling(
        { columns: options.columns, actions: options.actions as string[] },
        ceiling,
        { humanDid, requestedAt: new Date() },
      );
      if (ceiling.credentialMaxTtlMs !== undefined) {
        assertExpiresInBound(options.expiresIn, ceiling.credentialMaxTtlMs);
      }

      if (
        parentConfig?.credentialExp &&
        Math.floor(Date.now() / 1000) > parentConfig.credentialExp
      ) {
        throw new Error(
          'Parent credential has expired. Re-authenticate with the AbaxxOne parent instance ' +
            'to obtain a fresh credential before issuing new agent credentials.',
        );
      }

      if (parentConfig) {
        try {
          const result = await issueCredentialFromParent(
            parentConfig.provider,
            parentConfig.accessToken,
            options.agent,
            { columns: options.columns, actions: options.actions, expiresIn: options.expiresIn, maxDepth: options.maxDepth },
          );
          return result.jwt;
        } catch (e) {
          if (!(e instanceof ParentCredentialRequestFailedError)) throw e;
          if (options.requireParent) {
            throw new Error(
              'Parent credential request failed and requireParent is set. ' +
                'Re-authenticate with the AbaxxOne parent instance or remove the requireParent flag.',
            );
          }
          logger.warn(
            '[agents] Parent credential request failed — falling back to ' +
              (sdk ? 'SDK' : 'local') +
              ' signing. Agent will receive a self-asserted credential.',
            { fallbackTo: sdk ? 'sdk' : 'local' },
          );
        }
      }

      if (options.requireParent && !parentConfig) {
        throw new Error(
          'requireParent is set but no parent provider is configured on this session.',
        );
      }

      if (sdk) {
        return issueCredentialWithSdk(sdk, humanDid, options);
      }
      if (!humanPrivateKey) {
        throw new Error('Cannot issue credentials without SDK or local private key');
      }
      return issueCredential(humanDid, humanPrivateKey, options);
    },

    revokeCredential: revokeCredentialHelper(verifier, sdk, undefined, logger),
  };
}

/** Mock session for demo harness and unit tests. Deterministic DID from humanName. */
export function createMockSession(
  verifier: VcVerifier,
  humanName = 'Demo Human',
  sdk?: IdSdkInstance,
  ceiling: ScopeCeiling = unrestrictedCeiling(),
): AuthenticatedSession {
  const env = process.env.NODE_ENV;
  if (env !== 'development' && env !== 'test') {
    throw new Error(
      `createMockSession is a development/test helper and must not run in ${env ?? 'production'}. ` +
        `Set NODE_ENV=development or NODE_ENV=test, or use the real session factory (createSessionFromDid / createOidcSession).`,
    );
  }

  const seed = createHash('sha256')
    .update('mock-human:' + humanName)
    .digest();
  const { did: humanDid, publicKey, privateKey } = generateDidKeyFromSeed(seed);

  verifier.registerKey(humanDid, publicKey);

  return {
    humanDid,
    email: `${humanName.toLowerCase().replace(/\s+/g, '.')}@demo.abaxx.tech`,
    scopeCeiling: ceiling,

    async issueCredential(options: IssueCredentialOptions): Promise<string> {
      assertScopeFitsInCeiling(
        { columns: options.columns, actions: options.actions as string[] },
        ceiling,
        { humanDid, requestedAt: new Date() },
      );
      if (ceiling.credentialMaxTtlMs !== undefined) {
        assertExpiresInBound(options.expiresIn, ceiling.credentialMaxTtlMs);
      }
      if (sdk) {
        const jwt = await issueCredentialWithSdk(sdk, humanDid, options).catch<null>(() => null);
        if (jwt !== null) return jwt;
      }
      return issueCredential(humanDid, privateKey, options);
    },

    revokeCredential: revokeCredentialHelper(verifier, sdk, 'in mock mode'),
  };
}

/** Create an AuthenticatedSession from a pre-obtained OIDC identity. */
export function createOidcSession(
  verifier: VcVerifier,
  identity: {
    humanDid: string;
    issuer: string;
    sub: string;
    email?: string;
    name?: string;
  },
  sdk?: IdSdkInstance,
  ceiling: ScopeCeiling = unrestrictedCeiling(),
  logger: Logger = getLogger(),
): AuthenticatedSession {
  const seed = createHash('sha256')
    .update(identity.issuer + '\x00' + identity.sub)
    .digest();

  const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
  const pkcs8Der = Buffer.concat([pkcs8Header, seed]);
  const privateKeyObj = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  const publicKeyObj = createPublicKey(privateKeyObj);
  const pubKeyDer = publicKeyObj.export({ type: 'spki', format: 'der' }) as Buffer;
  const rawPublicKey = new Uint8Array(pubKeyDer.subarray(-32));

  const humanDid =
    identity.humanDid ||
    (() => {
      const multicodec = new Uint8Array(2 + rawPublicKey.length);
      multicodec[0] = 0xed;
      multicodec[1] = 0x01;
      multicodec.set(rawPublicKey, 2);
      return `did:key:z${base58Encode(multicodec)}`;
    })();

  verifier.registerKey(humanDid, rawPublicKey);

  const privateKey = new Uint8Array(
    (privateKeyObj.export({ type: 'pkcs8', format: 'der' }) as Buffer).subarray(16),
  );

  return {
    humanDid,
    email: identity.email,
    scopeCeiling: ceiling,

    async issueCredential(options: IssueCredentialOptions): Promise<string> {
      assertScopeFitsInCeiling(
        { columns: options.columns, actions: options.actions as string[] },
        ceiling,
        { humanDid, requestedAt: new Date() },
      );
      if (ceiling.credentialMaxTtlMs !== undefined) {
        assertExpiresInBound(options.expiresIn, ceiling.credentialMaxTtlMs);
      }
      if (sdk) {
        const jwt = await issueCredentialWithSdk(sdk, humanDid, options).catch<null>(() => null);
        if (jwt !== null) return jwt;
      }
      return issueCredential(humanDid, privateKey, options);
    },

    revokeCredential: revokeCredentialHelper(verifier, sdk, 'for OIDC session', logger),
  };
}
