import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runMigrateCheck, categorize, type Hit } from '#cli/migrate-check.js';

let fixtureRoot: string;

beforeEach(() => {
  fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-check-test-'));
});

afterEach(() => {
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
});

function writeFile(relPath: string, content: string): string {
  const full = path.join(fixtureRoot, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

async function captureStdout(fn: () => Promise<void>): Promise<{ stdout: string; stderr: string }> {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  const logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    stdoutChunks.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
  });
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    stderrChunks.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
  });
  try {
    await fn();
  } finally {
    logSpy.mockRestore();
    errSpy.mockRestore();
  }
  return { stdout: stdoutChunks.join('\n'), stderr: stderrChunks.join('\n') };
}

describe('migrate-check: env-read pattern', () => {
  it('detects dot-notation: process.env.AGENTS_MASTER_KEY', async () => {
    writeFile(
      'src/server.ts',
      `
      const masterKey = process.env.AGENTS_MASTER_KEY;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(1);
    expect(out.hits[0]).toMatchObject({ type: 'env-read', file: 'src/server.ts' });
  });

  it("detects bracket-notation: process.env['AGENTS_MASTER_KEY']", async () => {
    writeFile(
      'src/server.ts',
      `
      const k1 = process.env['AGENTS_MASTER_KEY'];
      const k2 = process.env["AGENTS_MASTER_KEY"];
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(2);
  });
});
describe('migrate-check: encryption.masterKey config pattern', () => {
  it('detects dot-path reference: encryption.masterKey', async () => {
    writeFile(
      'src/types.ts',
      `
      // The encryption.masterKey field is removed at the type level in v0.9.10.0.
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.configMasterKey).toBe(1);
  });
});

describe('migrate-check: AgentScope.create pattern', () => {
  it('detects call sites', async () => {
    writeFile(
      'src/index.ts',
      `
      const scope1 = await AgentScope.create(config);
      const scope2 = await AgentScope.create({ ... }, { masterKey });
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.agentscopeCreate).toBe(2);
  });
});

describe('migrate-check: categorize()', () => {
  it('env-reads AND config → trap', () => {
    const hits: Hit[] = [
      { file: 'src/a.ts', line: 1, type: 'env-read', snippet: '...' },
      { file: 'src/a.ts', line: 2, type: 'config-master-key', snippet: '...' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('trap');
    expect(result.guidance.join(' ')).toContain('Environment audit');
  });
});

describe('migrate-check: directory walking', () => {
  it('skips node_modules, dist, .git, and dot-directories', async () => {
    writeFile('src/server.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('node_modules/some-pkg/index.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('dist/server.js', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('.git/HEAD', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('.cache/build.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('coverage/lcov-report/index.ts', 'process.env.AGENTS_MASTER_KEY;');

    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(1);
    expect(out.hits[0].file).toBe('src/server.ts');
  });
});

describe('migrate-check: read-only invariant', () => {
  it('never writes to the scanned tree', async () => {
    writeFile('src/server.ts', 'const k = process.env.AGENTS_MASTER_KEY;');
    writeFile('src/scope.ts', 'const s = AgentScope.create(c);');

    const snapshot = (): string[] => {
      const result: string[] = [];
      const walk = (dir: string) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else if (entry.isFile()) {
            const stat = fs.statSync(full);
            const content = fs.readFileSync(full, 'utf8');
            result.push(`${full}|${stat.size}|${content}`);
          }
        }
      };
      walk(fixtureRoot);
      return result.sort();
    };

    const before = snapshot();
    await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot }));
    const after = snapshot();

    expect(after).toEqual(before);
  });
});

describe('migrate-check: output format', () => {
  it('json mode emits parseable JSON with counts, categorization, hits', async () => {
    writeFile('src/server.ts', 'const k = process.env.AGENTS_MASTER_KEY;');
    writeFile('src/scope.ts', 'AgentScope.create(c);');

    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));

    const parsed = JSON.parse(stdout);
    expect(parsed).toHaveProperty('root');
    expect(parsed).toHaveProperty('counts');
    expect(parsed).toHaveProperty('categorization');
    expect(parsed).toHaveProperty('hits');
    expect(parsed.counts.envReads).toBe(1);
    expect(parsed.counts.agentscopeCreate).toBe(1);
    expect(parsed.categorization.caseId).toBe('#1');
    expect(parsed.hits).toHaveLength(2);
  });
});
