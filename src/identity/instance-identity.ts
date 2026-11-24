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

/** The persistent server identity of an instance and the trust anchors stored beside it. */

import { LocalTrustAnchorStore } from '#discovery/trust-anchor.js';
import type { Logger } from '#observability/logger.js';
import { createKeystore, type KeystoreBackend } from './keystore.js';
import { initializeServerIdentity, type ServerIdentity } from './server-identity.js';
import type { VcVerifier } from './vc-verifier.js';

export interface InstanceIdentityOptions {
  /** JSON keystore path. Omit for the platform default (macOS Keychain outside CI and dev mode). */
  keystorePath?: string;
  /** Force the JSON file keystore. Hosts bridge this from their dev-mode flag. */
  devMode?: boolean;
  /** Server DIDs trusted from configuration; hosts bridge them from AGENTS_TRUSTED_SERVERS. */
  trustedServers?: readonly string[];
  /** Registers the server public key for local verification when given. */
  verifier?: VcVerifier;
  logger?: Logger;
}

export interface InstanceIdentity {
  serverIdentity: ServerIdentity;
  trustAnchors: LocalTrustAnchorStore;
  keystore: KeystoreBackend;
}

/**
 * The persistent server identity and its trust-anchor store, loaded from the
 * keystore. Stable across restarts, which is what lets peers keep trusting it.
 */
export async function createInstanceIdentity(
  options: InstanceIdentityOptions = {},
): Promise<InstanceIdentity> {
  const keystore = createKeystore({
    customPath: options.keystorePath,
    devMode: options.devMode,
    logger: options.logger,
  });
  const serverIdentity = await initializeServerIdentity(keystore, options.verifier);
  const trustAnchors = new LocalTrustAnchorStore({
    ownServerDid: serverIdentity.did,
    keystore,
    initialTrustedServers: options.trustedServers,
  });
  await trustAnchors.load();
  return { serverIdentity, trustAnchors, keystore };
}
