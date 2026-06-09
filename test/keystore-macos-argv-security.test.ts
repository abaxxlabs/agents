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

  it('read() returns secret from stdout; argv has no secret substring', async () => {
    const backend = new MacOsKeychainBackend('agents-test-argv', undefined, (args, stdin) => {
      calls.push({ args, stdin });
      const argv = ['/usr/bin/security', ...args];
      expect(argv.join('\0').includes(secret)).toBe(false);
      return {
        ok: true,
        stdout: `${secret}\n`,
        stderr: '',
        status: 0,
      };
    });

    const out = await backend.read('lookup-key');

    expect(out).toBe(secret);
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      const argv = ['/usr/bin/security', ...call.args];
      expect(argv.join('\0').includes(secret)).toBe(false);
    }
  });

  it('write() duplicate path (-U retry) still keeps secret out of argv', async () => {
    let callIdx = 0;
    const backend = new MacOsKeychainBackend('agents-test-argv', undefined, (args, stdin) => {
      calls.push({ args, stdin });
      const argv = ['/usr/bin/security', ...args];
      expect(argv.join('\0').includes(secret)).toBe(false);
      expect(String(stdin ?? '')).toBe(secret);
      callIdx += 1;
      if (callIdx === 1) {
        return {
          ok: false,
          stdout: '',
          stderr: 'security: SecKeychainItemCreateFromContent (-25299)',
          status: 45,
        };
      }
      return {
        ok: true,
        stdout: '',
        stderr: '',
        status: 0,
      };
    });

    await backend.write('dup-key', secret);

    expect(calls.length).toBe(2);
    const secondArgv = ['/usr/bin/security', ...calls[1].args];
    expect(secondArgv.includes('-U')).toBe(true);
    expect(secondArgv.join('\0').includes(secret)).toBe(false);
  });
});
