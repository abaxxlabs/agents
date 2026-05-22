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

import type {
  CreateAgentOptions,
  RegisteredAgent,
} from '../types/auth.js';
import type { AgentStore, AgentRecord } from '../storage/types.js';
import { VcVerifier } from '../vc-verifier.js';
import { generateDidKey, createSigner } from './did-key.js';
import { wrapColumnKey, unwrapColumnKey, isUndefinedTableError } from '../column-encryption.js';
import type { MasterKey } from '../crypto/master-key.js';
import {
  DecryptionFailedError,
  MasterKeyMismatchError,
} from '../errors/index.js';
import type { IdSdkInstance } from '../types/id-sdk.js';
import type { Logger } from '../logger.js';
import { getLogger } from '../logger.js';

/** Create a new agent identity (DID + key pair), persist it, and register the public key. */
export async function createAgent(
  agents: AgentStore,
  options: CreateAgentOptions & { ownerDid: string },
  verifier: VcVerifier,
  // Unused; kept for API compat. SDK DID creation hides the private key in HSM/KMS -- local key gen required.
  _sdk?: IdSdkInstance,
  masterKey?: MasterKey,
): Promise<RegisteredAgent> {
  const local = generateDidKey();
  const did = local.did;
  const publicKey = local.publicKey;

  const signer = createSigner(local.privateKey);

  if (masterKey) {
    const wrappedKey = wrapColumnKey(Buffer.from(local.privateKey), masterKey);
    await agents.create({
      did,
      name: options.name,
      ownerDid: options.ownerDid,
      encryptedPrivateKey: wrappedKey,
      publicKey: Buffer.from(publicKey),
    });
  } else {
    await agents.create({
      did,
      name: options.name,
      ownerDid: options.ownerDid,
    });
  }

  verifier.registerKey(did, publicKey);

  return {
    did,
    name: options.name,
    ownerDid: options.ownerDid,
    signer,
    publicKey,
  };
}

/** Either the restored agents map, or a sentinel when the `agents` table doesn't exist yet. */
export type RestoreAgentsResult = Map<string, RegisteredAgent> | { schemaMissing: true };

/** Restore persisted agents on startup: unwrap encrypted keys, recreate signers, register with verifier. */
export async function restoreAgents(
  agents: AgentStore,
  masterKey: MasterKey,
  verifier: VcVerifier,
  logger: Logger = getLogger(),
): Promise<RestoreAgentsResult> {
  let rows: AgentRecord[];
  try {
    rows = await agents.listAll();
  } catch (err) {
    if (isUndefinedTableError(err)) {
      return { schemaMissing: true };
    }
    throw err;
  }

  const restoredAgents = new Map<string, RegisteredAgent>();
  let restored = 0;
  let nullKeySkipped = 0;
  let decryptFailures = 0;
  let totalDecryptCandidates = 0;

  for (const r of rows) {
    if (!r.encryptedPrivateKey || !r.publicKey) {
      nullKeySkipped++;
      continue;
    }

    totalDecryptCandidates++;
    try {
      const privateKey = new Uint8Array(unwrapColumnKey(r.encryptedPrivateKey, masterKey));
      const signer = createSigner(privateKey);
      const publicKey = new Uint8Array(r.publicKey);

      verifier.registerKey(r.did, publicKey);

      restoredAgents.set(r.did, {
        did: r.did,
        name: r.name,
        ownerDid: r.ownerDid,
        signer,
        publicKey,
      });
      restored++;
    } catch (err) {
      if (err instanceof DecryptionFailedError) {
        decryptFailures++;
        logger.error(`[agents] Failed to decrypt agent ${r.did} — wrong master key for this row`, { agentDid: r.did });
      } else {
        throw err;
      }
    }
  }

  if (totalDecryptCandidates > 0 && restoredAgents.size === 0 && decryptFailures > 0) {
    throw new MasterKeyMismatchError(decryptFailures, totalDecryptCandidates);
  }

  if (restored > 0 || nullKeySkipped > 0 || decryptFailures > 0) {
    const skipParts: string[] = [];
    if (nullKeySkipped > 0) skipParts.push(`${nullKeySkipped} no-key`);
    if (decryptFailures > 0) skipParts.push(`${decryptFailures} decrypt-failed`);
    const skipNote = skipParts.length > 0 ? ` (skipped: ${skipParts.join(', ')})` : '';
    logger.error(`[agents] Restored ${restored} agents from database${skipNote}`, {
      restored, nullKeySkipped, decryptFailures,
    });
  }

  return restoredAgents;
}
