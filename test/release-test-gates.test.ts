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

import { afterEach, describe, expect, it, vi } from 'vitest';
import defaultConfig, { defaultTestExclude } from '../vitest.config.ts';
import e2eConfig, { e2eTestInclude } from '../vitest.e2e.config.ts';
import {
  ABAXX_ONE_OIDC_TESTS_ENV,
  KEYCHAIN_TESTS_ENV,
  LOOPBACK_TESTS_ENV,
} from './support/integration-gates.ts';
import {
  LINT_MAX_WARNINGS,
  RELEASE_GATE_COMMAND_STEPS,
  formatDirtyTreeFailure,
} from '../scripts/release-gate.mjs';

function testOptions(config: unknown): { include?: string[]; exclude?: string[] } {
  return (config as { test?: { include?: string[]; exclude?: string[] } }).test ?? {};
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('release-readiness test gates', () => {
  it('keeps listener and service integration suites out of default npm test', () => {
    expect(testOptions(defaultConfig).exclude).toEqual(expect.arrayContaining(defaultTestExclude));
  });

  it('keeps moved integration suites wired into the explicit e2e command', () => {
    expect(testOptions(e2eConfig).include).toEqual(expect.arrayContaining(e2eTestInclude));
  });

  it('keeps integration opt-in flags fail-closed under a clean environment', async () => {
    vi.stubEnv(KEYCHAIN_TESTS_ENV, undefined);
    vi.stubEnv(LOOPBACK_TESTS_ENV, undefined);
    vi.stubEnv(ABAXX_ONE_OIDC_TESTS_ENV, undefined);
    vi.resetModules();

    const gates = await import('./support/integration-gates.ts');

    expect(gates.shouldRunMacOsKeychainTests).toBe(false);
    expect(gates.shouldRunLoopbackHttpTests).toBe(false);
    expect(gates.shouldRunAbaxxOneOidcTests).toBe(false);
  });

  it('uses the root bun.lock install path instead of npm ci', () => {
    expect(RELEASE_GATE_COMMAND_STEPS[0]).toEqual({
      label: 'Install dependencies from bun.lock',
      command: 'bun',
      args: ['install', '--frozen-lockfile'],
    });

    expect(
      RELEASE_GATE_COMMAND_STEPS.some((step) => step.command === 'npm' && step.args[0] === 'ci'),
    ).toBe(false);
  });

  it('pins the release lint warning ceiling', () => {
    const lintStep = RELEASE_GATE_COMMAND_STEPS.find((step) => step.label === 'Lint source');

    expect(LINT_MAX_WARNINGS).toBe('387');
    expect(lintStep).toEqual({
      label: 'Lint source',
      command: 'npm',
      args: ['run', 'lint', '--', '--max-warnings=387'],
    });
  });

  it('keeps public API, clean build, pack, and publish checks ordered', () => {
    const labels = RELEASE_GATE_COMMAND_STEPS.map((step) => step.label);

    expect(labels.indexOf('Type-check source')).toBeLessThan(
      labels.indexOf('Check public API snapshot'),
    );
    expect(labels.indexOf('Check public API snapshot')).toBeLessThan(labels.indexOf('Lint source'));
    expect(labels.indexOf('Run tests')).toBeLessThan(labels.indexOf('Clean dist'));
    expect(labels.indexOf('Clean dist')).toBeLessThan(labels.indexOf('Build package'));
    expect(labels.indexOf('Build package')).toBeLessThan(labels.indexOf('Verify npm pack dry-run'));
    expect(labels.indexOf('Assert package metadata artifacts')).toBeLessThan(
      labels.indexOf('Audit package artifact guardrails'),
    );
    expect(labels.indexOf('Audit package artifact guardrails')).toBeLessThan(
      labels.indexOf('Verify npm pack dry-run'),
    );
    expect(labels.at(-1)).toBe('Verify npm publish dry-run');
  });

  it('keeps the package artifact audit wired into the release gate', () => {
    expect(RELEASE_GATE_COMMAND_STEPS).toEqual(
      expect.arrayContaining([
        {
          label: 'Audit package artifact guardrails',
          command: 'npm',
          args: ['run', 'audit:package-files'],
        },
      ]),
    );
  });

  it('runs pack and publish dry-runs without lifecycle scripts', () => {
    expect(RELEASE_GATE_COMMAND_STEPS).toEqual(
      expect.arrayContaining([
        {
          label: 'Verify npm pack dry-run',
          command: 'npm',
          args: ['pack', '--dry-run', '--ignore-scripts'],
        },
        {
          label: 'Verify npm publish dry-run',
          command: 'npm',
          args: ['publish', '--dry-run', '--ignore-scripts'],
        },
      ]),
    );
  });

  it('prints actionable guidance for dirty release gate checkouts', () => {
    const message = formatDirtyTreeFailure(' M package.json\n?? tmp-dirty-file\n');

    expect(message).toContain('requires a clean working tree');
    expect(message).toContain('before it installs, builds, or packs');
    expect(message).toContain('Commit, stash, or remove');
    expect(message).toContain('  M package.json');
    expect(message).toContain('  ?? tmp-dirty-file');
  });
});
