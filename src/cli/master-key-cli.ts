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

import { readSync } from 'node:fs';
import { parseMasterKeyHex } from '#bootstrap/index.js';
import type { MasterKey } from '#crypto/master-key.js';

const DEPRECATED_FLAG = '--master-key';
export const MAX_STDIN_MASTER_KEY_BYTES = 1024;

/**
 * Detects removed argv-based master-key flags before Commander parses options.
 */
export function argvContainsDeprecatedMasterKeyFlag(argv: string[]): boolean {
  for (const arg of argv) {
    if (arg === DEPRECATED_FLAG) return true;
    if (/^--master-key=/.test(arg) && !arg.startsWith('--master-key-stdin')) return true;
  }
  return false;
}

/**
 * Prints guidance for callers still passing master-key material on argv.
 */
export function printMasterKeyArgvRejected(): void {
  console.error(
    '[agents] Passing the master key on the command line is not supported (it appears in process listings and shell history).',
  );
  console.error(
    '[agents] Set AGENTS_MASTER_KEY in the environment, or use --master-key-stdin to supply the key from stdin until EOF.',
  );
}

/**
 * Warns only when the process started with AGENTS_MASTER_KEY already present.
 */
export function warnIfMasterKeyEnvWasPresentAtProcessStart(
  wasPresentAtProcessStart = masterKeyEnvWasPresentAtProcessStart,
): void {
  if (!wasPresentAtProcessStart) return;
  console.warn(
    '[agents] AGENTS_MASTER_KEY is set in this environment. If you exported it on the same command line as this invocation, it may be recorded in shell history.',
  );
}

function masterKeyEnvPresent(): boolean {
  const v = process.env.AGENTS_MASTER_KEY;
  return v !== undefined && v !== '';
}

// Capture at import time, before --master-key-stdin can populate process.env.
const masterKeyEnvWasPresentAtProcessStart = masterKeyEnvPresent();

/**
 * Parses a stdin buffer as a hex master key and zeroes the input buffer.
 */
export function parseMasterKeyFromRawStdinBuffer(rawBuf: Buffer): MasterKey {
  try {
    if (rawBuf.byteLength > MAX_STDIN_MASTER_KEY_BYTES) {
      throw new Error(
        `Master key stdin input is too large (max ${MAX_STDIN_MASTER_KEY_BYTES} bytes).`,
      );
    }
    const hex = rawBuf.toString('utf8').trim();
    return parseMasterKeyHex(hex);
  } finally {
    rawBuf.fill(0);
  }
}

/**
 * Reads stdin with a small upper bound so a pipe cannot feed unbounded data.
 */
export function readMasterKeyStdinBufferWithLimitSync(
  fd = 0,
  maxBytes = MAX_STDIN_MASTER_KEY_BYTES,
): Buffer {
  const scratch = Buffer.allocUnsafe(maxBytes + 1);
  let total = 0;

  try {
    while (true) {
      const bytesRead = readSync(fd, scratch, total, scratch.byteLength - total, null);
      if (bytesRead === 0) break;

      total += bytesRead;
      if (total > maxBytes) {
        throw new Error(`Master key stdin input is too large (max ${maxBytes} bytes).`);
      }
    }

    return Buffer.from(scratch.subarray(0, total));
  } finally {
    scratch.fill(0);
  }
}

/**
 * Reads and parses a master key from stdin unless stdin is an interactive TTY.
 */
export function readParseMasterKeyFromStdinSync(
  stdin: Pick<NodeJS.ReadStream, 'isTTY'> = process.stdin,
): MasterKey {
  if (stdin.isTTY) {
    throw new Error(
      'Refusing to read --master-key-stdin from an interactive TTY. Use: agents init --master-key-stdin < keyfile',
    );
  }
  return parseMasterKeyFromRawStdinBuffer(readMasterKeyStdinBufferWithLimitSync());
}

/**
 * Applies --master-key-stdin to process.env for CLI commands that already read env.
 */
export function applyStdinMasterKeyToEnv(): void {
  const mk = readParseMasterKeyFromStdinSync();
  try {
    process.env.AGENTS_MASTER_KEY = mk.toString('hex');
  } finally {
    mk.fill(0);
  }
}
