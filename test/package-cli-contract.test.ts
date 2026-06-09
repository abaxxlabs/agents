import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const NPM_CACHE = join(tmpdir(), 'agents-cli-contract-npm-cache');
let githubToken: string | undefined;

interface SpawnResult {
  stdout: string;
  stderr: string;
}

function resolveGithubToken(): string | undefined {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  if (githubToken !== undefined) return githubToken || undefined;

  const result = spawnSync('gh', ['auth', 'token'], { encoding: 'utf8' });
  githubToken = result.status === 0 ? result.stdout.trim() : '';
  return githubToken || undefined;
}

function run(command: string, args: string[], cwd = ROOT): SpawnResult {
  const token = resolveGithubToken();
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...(token ? { GITHUB_TOKEN: token } : {}),
      NO_COLOR: '1',
      npm_config_cache: NPM_CACHE,
      npm_config_fetch_retries: '1',
      npm_config_fetch_retry_maxtimeout: '5000',
      npm_config_fetch_retry_mintimeout: '1000',
      npm_config_fetch_timeout: '30000',
    },
  });

  if (result.status !== 0) {
    throw new Error(
      [
        `${command} ${args.join(' ')} failed with status ${result.status}`,
        result.stdout,
        result.stderr,
      ]
        .filter(Boolean)
        .join('\n'),
    );
  }

  return {
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function parsePackJson(
  stdout: string,
): Array<{ filename: string; files: Array<{ path: string }> }> {
  return JSON.parse(stdout) as Array<{ filename: string; files: Array<{ path: string }> }>;
}

describe('package CLI contract', () => {
  let tempRoot: string;

  beforeAll(() => {
    tempRoot = mkdtempSync(join(tmpdir(), 'agents-cli-contract-'));
    run('npm', ['run', 'clean']);
    run('npm', ['run', 'build']);
  });

  afterAll(() => {
    if (tempRoot) rmSync(tempRoot, { recursive: true, force: true });
  });

  it('advertises a bin target that exists in the dry-run tarball', () => {
    const pkg = JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8')) as {
      bin?: Record<string, string>;
    };

    const binTarget = pkg.bin?.agents;
    expect(binTarget).toBe('./dist/cli/index.js');
    if (!binTarget) throw new Error('package.json is missing bin.agents');
    expect(existsSync(resolve(ROOT, binTarget))).toBe(true);

    const cliEntry = readFileSync(resolve(ROOT, binTarget), 'utf8');
    expect(cliEntry).not.toMatch(
      /from ['"]\.\/(?:demo|encrypt|init|migrate-check|status|verify)\.js['"]/,
    );
    expect(cliEntry).not.toContain("from '../mcp/index.js'");
    expect(cliEntry).toContain("await import('./migrate-check.js')");

    const dryRun = parsePackJson(run('npm', ['pack', '--dry-run', '--json']).stdout);
    const files = dryRun[0].files.map((file) => file.path);

    expect(files).toContain('package.json');
    expect(files).toContain('dist/cli/index.js');
    expect(files.filter((file) => file.includes('rest-bridge'))).toEqual([]);
  }, 120_000);

  it('installs from a packed tarball and runs CLI help for every command', () => {
    const packDir = join(tempRoot, 'pack');
    const installDir = join(tempRoot, 'install');
    mkdirSync(packDir, { recursive: true });
    mkdirSync(installDir, { recursive: true });

    const rootNpmrc = resolve(ROOT, '.npmrc');
    if (existsSync(rootNpmrc)) {
      copyFileSync(rootNpmrc, join(installDir, '.npmrc'));
    }

    const pack = parsePackJson(
      run('npm', ['pack', '--json', '--pack-destination', packDir]).stdout,
    );
    const tarball = resolve(packDir, pack[0].filename);
    const binName = process.platform === 'win32' ? 'agents.cmd' : 'agents';

    run(
      'npm',
      [
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--omit=optional',
        '--package-lock=false',
        tarball,
      ],
      installDir,
    );

    const help = run(join(installDir, 'node_modules', '.bin', binName), ['--help'], installDir);

    expect(help.stdout).toContain('Usage: agents [options] [command]');
    expect(help.stdout).toContain('migrate-check');

    for (const command of [
      'init',
      'demo',
      'encrypt',
      'verify',
      'status',
      'mcp',
      'migrate-check',
      'serve',
    ]) {
      const commandHelp = run(
        join(installDir, 'node_modules', '.bin', binName),
        [command, '--help'],
        installDir,
      );
      expect(commandHelp.stdout).toContain(`Usage: agents ${command}`);
    }
  }, 120_000);
});
