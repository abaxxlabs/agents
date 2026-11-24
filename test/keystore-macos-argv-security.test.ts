import { describe, it, expect, beforeEach } from 'vitest';
import { MacOsKeychainBackend } from '#identity/keystore.js';

describe('MacOsKeychainBackend — secret never in argv', () => {
  const secret = 'super-secret-key-material-not-in-argv-xyz';
  const calls: Array<{ args: string[]; stdin?: string | Buffer }> = [];

  beforeEach(() => {
    calls.length = 0;
  });

  it('write() feeds the secret via stdin; argv has no secret substring', async () => {
    const backend = new MacOsKeychainBackend('agents-test-argv', undefined, (args, stdin) => {
      calls.push({ args, stdin });
      const argv = ['/usr/bin/security', ...args];
      expect(argv.join('\0').includes(secret)).toBe(false);
      expect(String(stdin ?? '')).toBe(secret);
      return {
        ok: true,
        stdout: '',
        stderr: '',
        status: 0,
      };
    });

    await backend.write('account-key', secret);

    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      const argv = ['/usr/bin/security', ...call.args];
      expect(argv.join('\0').includes(secret)).toBe(false);
    }
  });
});
