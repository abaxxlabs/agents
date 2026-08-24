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

import { AgentScopeError } from './base.js';

/**
 * Phase tag for KeyRotationFailedError.
 *
 * Phases in order for rotateColumnKey:
 *   'unwrap-old-key' -- failed to decrypt the wrapped column key from agent_keys.
 *   'decrypt-row' -- GCM auth tag failure on a data row during re-encryption pass.
 *   'encrypt-row' -- AES-GCM cipher error while re-encrypting. Extremely rare.
 *   'wrap-new-key' -- failed to wrap the new column key under the master key.
 *   'update-agent-keys' -- failed to UPDATE agent_keys with the new wrapped key.
 *   'audit-append' -- failed to write the audit record inside the transaction.
 *
 * For rewrapColumnKey, only: 'unwrap-old-key', 'wrap-new-key',
 * 'update-agent-keys', 'audit-append' -- no row-level phases.
 */
export type KeyRotationPhase =
  | 'unwrap-old-key'
  | 'decrypt-row'
  | 'encrypt-row'
  | 'wrap-new-key'
  | 'update-agent-keys'
  | 'audit-append';

/**
 * Thrown by rotateColumnKey() and rewrapColumnKey() on any failure.
 * The phase field identifies WHERE in the operation the failure occurred.
 */
export class KeyRotationFailedError extends Error {
  constructor(
    public readonly phase: KeyRotationPhase,
    public override readonly cause: unknown,
  ) {
    super(`Key rotation failed at phase '${phase}': ${(cause as Error)?.message ?? String(cause)}`);
    this.name = 'KeyRotationFailedError';
  }
}

export class DecryptionFailedError extends AgentScopeError {
  constructor(column: string, reason?: string) {
    super(
      'DECRYPTION_FAILED',
      `Failed to decrypt column '${column}'${reason ? ` — ${reason}` : ''}`,
      { column },
    );
    this.name = 'DecryptionFailedError';
  }
}

export class MasterKeyMissingError extends AgentScopeError {
  constructor() {
    super(
      'MASTER_KEY_MISSING',
      // Points at parseMasterKeyHex (not raw Buffer.from) because Buffer.from silently drops
      // non-hex characters and produces an undersized buffer.
      "Master key not provided. Pass a 32-byte Buffer as injections.masterKey to AgentScope.create(config, injections). For env-var bootstrap, import parseMasterKeyHex from '@abaxxlabs/agents/bootstrap' (strict 64-hex validation). See docs/migrations/byok.md for full examples.",
      {},
    );
    this.name = 'MasterKeyMissingError';
  }
}

/**
 * Thrown when persisted column keys exist but cannot be decrypted with the supplied master key.
 * Mass-fail (not any-fail): legitimate rotation states can briefly mix old + new wrapped keys.
 */
export class MasterKeyMismatchError extends AgentScopeError {
  constructor(failedCount: number, totalCount?: number) {
    super(
      'MASTER_KEY_MISMATCH',
      'Column keys exist but cannot be decrypted with the provided master key. Wrong key or corrupted data.',
      { failedCount, ...(totalCount !== undefined ? { totalCount } : {}) },
    );
    this.name = 'MasterKeyMismatchError';
  }
}
