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

// Asserts MacOsKeychainBackend never places the secret in argv (module-mocked because ESM namespace exports aren't spyable with vi.spyOn).

import { describe, it, expect, beforeEach, vi, type MockedFunction } from 'vitest';

vi.mock('node:child_process', () => ({
  spawnSync: vi.fn(),
  execSync: vi.fn(),
}));

import { spawnSync, execSync } from 'node:child_process';

// vi.mocked() unavailable under Bun — manual cast
function asMock<T extends (...args: any[]) => any>(fn: T): MockedFunction<T> {
  return fn as MockedFunction<T>;
}
import { MacOsKeychainBackend } from '../src/identity/keystore.js';

describe('MacOsKeychainBackend — secret never in argv', () => {
  const secret = 'super-secret-key-material-not-in-argv-xyz';

  beforeEach(() => {
    asMock(spawnSync).mockReset();
    asMock(execSync).mockReset();
    asMock(execSync).mockImplementation(() => {
      throw new Error('execSync must not be used for keychain secret I/O');
    });
  });

  it('write() feeds the secret via stdin; argv has no secret substring', async () => {
    asMock(spawnSync).mockImplementation((command, args, options) => {
      const argv = [String(command), ...((args as string[] | undefined) ?? [])];
      expect(argv.join('\0').includes(secret)).toBe(false);
      const input = options && typeof options === 'object' && 'input' in options ? options.input : undefined;
      expect(String(input ?? '')).toBe(secret);
      return {
        status: 0,
        stdout: '',
        stderr: '',
        signal: null,
        error: undefined,
        pid: 1,
        output: ['', ''],
      };
    });

    const backend = new MacOsKeychainBackend('agents-test-argv');
    await backend.write('account-key', secret);

    expect(asMock(spawnSync)).toHaveBeenCalled();
    expect(asMock(execSync)).not.toHaveBeenCalled();
    for (const call of asMock(spawnSync).mock.calls) {
      const argv = [String(call[0]), ...((call[1] as string[] | undefined) ?? [])];
      expect(argv.join('\0').includes(secret)).toBe(false);
    }
  });

  it('read() returns secret from stdout; argv has no secret substring', async () => {
    asMock(spawnSync).mockImplementation((command, args) => {
      const argv = [String(command), ...((args as string[] | undefined) ?? [])];
      expect(argv.join('\0').includes(secret)).toBe(false);
      return {
        status: 0,
        stdout: `${secret}\n`,
        stderr: '',
        signal: null,
        error: undefined,
        pid: 1,
        output: [`${secret}\n`, ''],
      };
    });

    const backend = new MacOsKeychainBackend('agents-test-argv');
    const out = await backend.read('lookup-key');

    expect(out).toBe(secret);
    expect(asMock(spawnSync)).toHaveBeenCalled();
    expect(asMock(execSync)).not.toHaveBeenCalled();
    for (const call of asMock(spawnSync).mock.calls) {
      const argv = [String(call[0]), ...((call[1] as string[] | undefined) ?? [])];
      expect(argv.join('\0').includes(secret)).toBe(false);
    }
  });

  it('write() duplicate path (-U retry) still keeps secret out of argv', async () => {
    let callIdx = 0;
    asMock(spawnSync).mockImplementation((command, args, options) => {
      const argv = [String(command), ...((args as string[] | undefined) ?? [])];
      expect(argv.join('\0').includes(secret)).toBe(false);
      expect(String((options as { input?: unknown })?.input ?? '')).toBe(secret);
      callIdx += 1;
      if (callIdx === 1) {
        return {
          status: 45,
          stdout: '',
          stderr: 'security: SecKeychainItemCreateFromContent (-25299)',
          signal: null,
          error: undefined,
          pid: 1,
          output: ['', ''],
        };
      }
      return {
        status: 0,
        stdout: '',
        stderr: '',
        signal: null,
        error: undefined,
        pid: 1,
        output: ['', ''],
      };
    });

    const backend = new MacOsKeychainBackend('agents-test-argv');
    await backend.write('dup-key', secret);

    expect(asMock(spawnSync).mock.calls.length).toBe(2);
    const secondArgv = [
      String(asMock(spawnSync).mock.calls[1][0]),
      ...((asMock(spawnSync).mock.calls[1][1] as string[] | undefined) ?? []),
    ];
    expect(secondArgv.includes('-U')).toBe(true);
    expect(secondArgv.join('\0').includes(secret)).toBe(false);
  });
});
