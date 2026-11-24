import { randomBytes } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  argvContainsDeprecatedMasterKeyFlag,
  parseMasterKeyFromRawStdinBuffer,
  readParseMasterKeyFromStdinSync,
} from '#cli/master-key-cli.js';

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
});

describe('readParseMasterKeyFromStdinSync', () => {
  it('rejects interactive TTY stdin before reading fd 0', () => {
    expect(() => readParseMasterKeyFromStdinSync({ isTTY: true })).toThrow(/interactive TTY/);
  });
});
