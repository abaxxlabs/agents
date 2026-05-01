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

import { randomBytes } from 'node:crypto';
import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import { buildServeChildEnv } from '../src/cli/serve-env.js';
import {
  argvContainsDeprecatedMasterKeyFlag,
  MAX_STDIN_MASTER_KEY_BYTES,
  parseMasterKeyFromRawStdinBuffer,
  readMasterKeyStdinBufferWithLimitSync,
  readParseMasterKeyFromStdinSync,
  warnIfMasterKeyEnvWasPresentAtProcessStart,
} from '../src/cli/master-key-cli.js';

describe('cli master-key argv guard', () => {
  it('detects --master-key with a following value', () => {
    expect(
      argvContainsDeprecatedMasterKeyFlag([
        'node',
        'agents',
        'init',
        '--master-key',
        'a'.repeat(64),
      ]),
    ).toBe(true);
  });

  it('detects --master-key even when the value is missing', () => {
    expect(argvContainsDeprecatedMasterKeyFlag(['node', 'agents', 'init', '--master-key'])).toBe(
      true,
    );
  });

  it('detects --master-key=<hex> form', () => {
    expect(
      argvContainsDeprecatedMasterKeyFlag([
        'agents',
        'encrypt',
        't.c',
        `--master-key=${'a'.repeat(64)}`,
      ]),
    ).toBe(true);
  });

  it('does not treat --master-key-stdin as deprecated', () => {
    expect(
      argvContainsDeprecatedMasterKeyFlag(['agents', 'encrypt', 't.c', '--master-key-stdin']),
    ).toBe(false);
  });

  it('does not treat --master-key-stdin=<hex> as deprecated', () => {
    expect(
      argvContainsDeprecatedMasterKeyFlag([
        'agents',
        'encrypt',
        't.c',
        `--master-key-stdin=${'b'.repeat(64)}`,
      ]),
    ).toBe(false);
  });

  it('does not false-positive unrelated flags', () => {
    expect(argvContainsDeprecatedMasterKeyFlag(['agents', 'init', '--db', 'x'])).toBe(false);
  });
});

describe('parseMasterKeyFromRawStdinBuffer', () => {
  it('parses trimmed hex and zeroes the input buffer', () => {
    const hex = randomBytes(32).toString('hex');
    const buf = Buffer.from(`  ${hex}  \n`, 'utf8');
    const copy = Buffer.from(buf);
    const mk = parseMasterKeyFromRawStdinBuffer(buf);
    expect(mk.length).toBe(32);
    expect(Buffer.from(hex, 'hex').equals(mk)).toBe(true);
    expect(buf.equals(copy)).toBe(false);
    expect(buf.every((b) => b === 0)).toBe(true);
    mk.fill(0);
  });

  it('rejects oversized input and zeroes the input buffer', () => {
    const buf = Buffer.alloc(MAX_STDIN_MASTER_KEY_BYTES + 1, 0x61);

    expect(() => parseMasterKeyFromRawStdinBuffer(buf)).toThrow(/too large/);
    expect(buf.every((b) => b === 0)).toBe(true);
  });
});

describe('readParseMasterKeyFromStdinSync', () => {
  it('rejects interactive TTY stdin before reading fd 0', () => {
    expect(() => readParseMasterKeyFromStdinSync({ isTTY: true })).toThrow(/interactive TTY/);
  });
});

describe('readMasterKeyStdinBufferWithLimitSync', () => {
  it('rejects stdin input larger than the cap', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agents-cli-'));
    const path = join(dir, 'master-key.txt');
    writeFileSync(path, 'a'.repeat(MAX_STDIN_MASTER_KEY_BYTES + 1));
    const fd = openSync(path, 'r');

    try {
      expect(() => readMasterKeyStdinBufferWithLimitSync(fd)).toThrow(/too large/);
    } finally {
      closeSync(fd);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('warnIfMasterKeyEnvWasPresentAtProcessStart', () => {
  it('warns only when the env var was present at process start', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    try {
      warnIfMasterKeyEnvWasPresentAtProcessStart(false);
      expect(warn).not.toHaveBeenCalled();

      warnIfMasterKeyEnvWasPresentAtProcessStart(true);
      expect(warn).toHaveBeenCalledTimes(1);
    } finally {
      warn.mockRestore();
    }
  });
});

describe('buildServeChildEnv', () => {
  it('passes an inherited AGENTS_MASTER_KEY through to the server process', () => {
    const env = buildServeChildEnv(
      { db: 'postgresql://localhost/agents', port: '3100', columns: 'patients.ssn' },
      {
        AGENTS_MASTER_KEY: 'a'.repeat(64),
        DATABASE_URL: 'postgresql://localhost/old',
      },
    );

    expect(env.AGENTS_MASTER_KEY).toBe('a'.repeat(64));
    expect(env.DATABASE_URL).toBe('postgresql://localhost/agents');
    expect(env.PORT).toBe('3100');
    expect(env.ENCRYPTED_COLUMNS).toBe('patients.ssn');
  });
});
