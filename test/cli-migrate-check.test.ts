import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runMigrateCheck, categorize, type Hit } from '#cli/migrate-check.js';

// ─── Fixture helpers ──────────────────────────────────────────────────────────

let fixtureRoot: string;

beforeEach(() => {
  fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-check-test-'));
});

afterEach(() => {
  // Recursive delete; best-effort on Windows where the rm recursive has
  // historically been touchy.
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

// ─── Pattern matching: env-read ───────────────────────────────────────────────

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

  it('detects destructure: const { AGENTS_MASTER_KEY } = process.env', async () => {
    writeFile(
      'src/server.ts',
      `
      const { AGENTS_MASTER_KEY } = process.env;
      const { DATABASE_URL, AGENTS_MASTER_KEY: alias } = process.env;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(2);
  });
});

// ─── Pattern matching: env-write ──────────────────────────────────────────────

describe('migrate-check: env-write pattern', () => {
  it('detects assignment: process.env.AGENTS_MASTER_KEY = ...', async () => {
    writeFile(
      'src/showcase.ts',
      `
      process.env.AGENTS_MASTER_KEY = masterKeyHex;
      process.env['AGENTS_MASTER_KEY'] = anotherKey;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envWrites).toBe(2);
    expect(out.counts.envReads).toBe(0); // write must not double-count as read
  });
});

// ─── Pattern matching: config-master-key ──────────────────────────────────────

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

  it('detects inline config object: encryption: { masterKey: ... }', async () => {
    writeFile(
      'src/server.ts',
      `
      const config = { encryption: { masterKey: '0'.repeat(64) } };
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.configMasterKey).toBe(1);
  });
});

// ─── Pattern matching: AgentScope.create ──────────────────────────────────────

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

// ─── Pattern matching: env-dev-mode ──────────────────────────────────────────

describe('migrate-check: env-dev-mode pattern', () => {
  it('detects dot-notation: process.env.AGENTS_DEV_MODE', async () => {
    writeFile(
      'src/server.ts',
      `
      const dev = process.env.AGENTS_DEV_MODE === 'true';
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envDevMode).toBe(1);
    expect(out.hits.find((h: Hit) => h.type === 'env-dev-mode')).toMatchObject({
      file: 'src/server.ts',
    });
  });

  it("detects bracket-notation: process.env['AGENTS_DEV_MODE']", async () => {
    writeFile(
      'src/server.ts',
      `
      const dev = process.env['AGENTS_DEV_MODE'];
      const dev2 = process.env["AGENTS_DEV_MODE"];
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envDevMode).toBe(2);
  });

  it('detects destructure: const { AGENTS_DEV_MODE } = process.env', async () => {
    writeFile(
      'src/server.ts',
      `
      const { AGENTS_DEV_MODE } = process.env;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envDevMode).toBe(1);
  });

  it('does NOT count toward BYOK envReads', async () => {
    writeFile(
      'src/server.ts',
      `
      const dev = process.env.AGENTS_DEV_MODE === 'true';
      const masterKey = process.env.AGENTS_MASTER_KEY;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    // BYOK case categorization is unchanged — envReads only counts AGENTS_MASTER_KEY.
    expect(out.counts.envReads).toBe(1);
    expect(out.counts.envDevMode).toBe(1);
  });

  it('advisory section appears in human-readable output when devMode hits exist', async () => {
    writeFile(
      'src/server.ts',
      `
      const dev = process.env.AGENTS_DEV_MODE === 'true';
    `,
    );
    const { stdout } = await captureStdout(() =>
      runMigrateCheck({ cwd: fixtureRoot, json: false }),
    );
    expect(stdout).toContain('AGENTS_DEV_MODE migration');
    expect(stdout).toContain('AgentScopeConfig.devMode');
  });
});

// ─── Pattern matching: env-keystore-path ─────────────────────────────────────

describe('migrate-check: env-keystore-path pattern', () => {
  it('detects dot-notation: process.env.AGENTS_KEYSTORE_PATH', async () => {
    writeFile(
      'src/server.ts',
      `
      const path = process.env.AGENTS_KEYSTORE_PATH ?? '/default/keystore.json';
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envKeystorePath).toBe(1);
    expect(out.hits.find((h: Hit) => h.type === 'env-keystore-path')).toMatchObject({
      file: 'src/server.ts',
    });
  });

  it("detects bracket-notation: process.env['AGENTS_KEYSTORE_PATH']", async () => {
    writeFile(
      'src/server.ts',
      `
      const a = process.env['AGENTS_KEYSTORE_PATH'];
      const b = process.env["AGENTS_KEYSTORE_PATH"];
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envKeystorePath).toBe(2);
  });

  it('detects destructure: const { AGENTS_KEYSTORE_PATH } = process.env', async () => {
    writeFile(
      'src/server.ts',
      `
      const { AGENTS_KEYSTORE_PATH } = process.env;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envKeystorePath).toBe(1);
  });

  it('does NOT count toward BYOK envReads or env-dev-mode', async () => {
    writeFile(
      'src/server.ts',
      `
      const path = process.env.AGENTS_KEYSTORE_PATH;
      const dev = process.env.AGENTS_DEV_MODE === 'true';
      const masterKey = process.env.AGENTS_MASTER_KEY;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    // Each variant counts only in its own bucket.
    expect(out.counts.envReads).toBe(1);
    expect(out.counts.envDevMode).toBe(1);
    expect(out.counts.envKeystorePath).toBe(1);
  });

  it('advisory section appears in human-readable output when keystore-path hits exist', async () => {
    writeFile(
      'src/server.ts',
      `
      const path = process.env.AGENTS_KEYSTORE_PATH;
    `,
    );
    const { stdout } = await captureStdout(() =>
      runMigrateCheck({ cwd: fixtureRoot, json: false }),
    );
    expect(stdout).toContain('AGENTS_KEYSTORE_PATH migration');
    expect(stdout).toContain('AgentScopeConfig.keystore.path');
  });
});

// ─── Pattern matching: env-trusted-servers ───────────────────────────────────

describe('migrate-check: env-trusted-servers pattern', () => {
  it('detects dot-notation: process.env.AGENTS_TRUSTED_SERVERS', async () => {
    writeFile(
      'src/server.ts',
      `
      const trusted = process.env.AGENTS_TRUSTED_SERVERS;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envTrustedServers).toBe(1);
    expect(out.hits.find((h: Hit) => h.type === 'env-trusted-servers')).toMatchObject({
      file: 'src/server.ts',
    });
  });

  it("detects bracket-notation: process.env['AGENTS_TRUSTED_SERVERS']", async () => {
    writeFile(
      'src/server.ts',
      `
      const a = process.env['AGENTS_TRUSTED_SERVERS'];
      const b = process.env["AGENTS_TRUSTED_SERVERS"];
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envTrustedServers).toBe(2);
  });

  it('detects destructure: const { AGENTS_TRUSTED_SERVERS } = process.env', async () => {
    writeFile(
      'src/server.ts',
      `
      const { AGENTS_TRUSTED_SERVERS } = process.env;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envTrustedServers).toBe(1);
  });

  it('does NOT count toward BYOK envReads or other config advisories', async () => {
    writeFile(
      'src/server.ts',
      `
      const trusted = process.env.AGENTS_TRUSTED_SERVERS;
      const dev = process.env.AGENTS_DEV_MODE === 'true';
      const masterKey = process.env.AGENTS_MASTER_KEY;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(1);
    expect(out.counts.envDevMode).toBe(1);
    expect(out.counts.envTrustedServers).toBe(1);
  });

  it('advisory section names the bootstrap helper and ctor option', async () => {
    writeFile(
      'src/server.ts',
      `
      const trusted = process.env.AGENTS_TRUSTED_SERVERS;
    `,
    );
    const { stdout } = await captureStdout(() =>
      runMigrateCheck({ cwd: fixtureRoot, json: false }),
    );
    expect(stdout).toContain('AGENTS_TRUSTED_SERVERS migration');
    expect(stdout).toContain('resolveTrustedServersFromEnv');
    expect(stdout).toContain('initialTrustedServers');
  });
});

// ─── Pattern matching: env-consumer-domains ──────────────────────────────────

describe('migrate-check: env-consumer-domains pattern', () => {
  it('detects dot-notation: process.env.AGENTS_CONSUMER_DOMAINS', async () => {
    writeFile(
      'src/server.ts',
      `
      const extra = process.env.AGENTS_CONSUMER_DOMAINS;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envConsumerDomains).toBe(1);
  });

  it("detects bracket-notation: process.env['AGENTS_CONSUMER_DOMAINS']", async () => {
    writeFile(
      'src/server.ts',
      `
      const a = process.env['AGENTS_CONSUMER_DOMAINS'];
      const b = process.env["AGENTS_CONSUMER_DOMAINS"];
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envConsumerDomains).toBe(2);
  });

  it('detects destructure: const { AGENTS_CONSUMER_DOMAINS } = process.env', async () => {
    writeFile(
      'src/server.ts',
      `
      const { AGENTS_CONSUMER_DOMAINS } = process.env;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envConsumerDomains).toBe(1);
  });

  it('does NOT count toward BYOK envReads or other config advisories', async () => {
    writeFile(
      'src/server.ts',
      `
      const consumer = process.env.AGENTS_CONSUMER_DOMAINS;
      const trusted = process.env.AGENTS_TRUSTED_SERVERS;
      const masterKey = process.env.AGENTS_MASTER_KEY;
    `,
    );
    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(1);
    expect(out.counts.envTrustedServers).toBe(1);
    expect(out.counts.envConsumerDomains).toBe(1);
  });

  it('advisory names BOTH engine call sites that consumers must wire', async () => {
    writeFile(
      'src/server.ts',
      `
      const extra = process.env.AGENTS_CONSUMER_DOMAINS;
    `,
    );
    const { stdout } = await captureStdout(() =>
      runMigrateCheck({ cwd: fixtureRoot, json: false }),
    );
    expect(stdout).toContain('AGENTS_CONSUMER_DOMAINS migration');
    expect(stdout).toContain('AgentScope.create');
    expect(stdout).toContain('GenericOidcProvider');
  });
});

// ─── categorize: config-advisory-only case ────────────────────────────────────

describe('migrate-check: categorize config-advisory-only', () => {
  it('categorize returns config-advisory-only when only config advisory hits exist', () => {
    const hits: Hit[] = [
      { file: 'src/server.ts', line: 1, type: 'env-dev-mode', snippet: '...' },
      { file: 'src/server.ts', line: 2, type: 'env-keystore-path', snippet: '...' },
      { file: 'src/server.ts', line: 3, type: 'env-trusted-servers', snippet: '...' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('config-advisory-only');
    expect(result.headline.toLowerCase()).toContain('library-shrink');
    expect(result.headline.toLowerCase()).toContain('v0.10.0');
  });

  it('categorize stays no-agents-code when ALL hit types are zero', () => {
    const result = categorize([]);
    expect(result.caseId).toBe('no-agents-code');
  });

  it('categorize prefers BYOK case over config-advisory-only when both signals present', () => {
    const hits: Hit[] = [
      { file: 'src/server.ts', line: 1, type: 'env-read', snippet: 'AGENTS_MASTER_KEY' },
      { file: 'src/server.ts', line: 2, type: 'env-dev-mode', snippet: 'AGENTS_DEV_MODE' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('#1'); // BYOK case wins
  });

  it('integration: config advisory fixture produces config-advisory-only headline alongside advisories', async () => {
    writeFile(
      'src/server.ts',
      `
      const dev = process.env.AGENTS_DEV_MODE;
      const path = process.env.AGENTS_KEYSTORE_PATH;
      const trusted = process.env.AGENTS_TRUSTED_SERVERS;
      const consumer = process.env.AGENTS_CONSUMER_DOMAINS;
    `,
    );
    const { stdout } = await captureStdout(() =>
      runMigrateCheck({ cwd: fixtureRoot, json: false }),
    );
    expect(stdout).toContain('Library-shrink');
    expect(stdout).toContain('v0.10.0');
    // Advisory sections still emit
    expect(stdout).toContain('AGENTS_DEV_MODE migration');
    expect(stdout).toContain('AGENTS_KEYSTORE_PATH migration');
    expect(stdout).toContain('AGENTS_TRUSTED_SERVERS migration');
    expect(stdout).toContain('AGENTS_CONSUMER_DOMAINS migration');
    expect(stdout).not.toContain('No @abaxxlabs/agents signals found');
  });
});

// ─── Categorization (pure-function tests, no fs) ──────────────────────────────

describe('migrate-check: categorize()', () => {
  it('no signals → no-agents-code', () => {
    const result = categorize([]);
    expect(result.caseId).toBe('no-agents-code');
  });

  it('env-reads only → case #1', () => {
    const hits: Hit[] = [
      { file: 'src/a.ts', line: 1, type: 'env-read', snippet: '...' },
      { file: 'src/a.ts', line: 2, type: 'agentscope-create', snippet: '...' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('#1');
    expect(result.headline.toLowerCase()).toContain('env-only');
  });

  it('config-only → case #2', () => {
    const hits: Hit[] = [{ file: 'src/a.ts', line: 1, type: 'config-master-key', snippet: '...' }];
    const result = categorize(hits);
    expect(result.caseId).toBe('#2');
    expect(result.headline.toLowerCase()).toContain('config-hex');
  });

  it('env-reads AND config → trap', () => {
    const hits: Hit[] = [
      { file: 'src/a.ts', line: 1, type: 'env-read', snippet: '...' },
      { file: 'src/a.ts', line: 2, type: 'config-master-key', snippet: '...' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('trap');
    expect(result.guidance.join(' ')).toContain('Environment audit');
  });

  it('AgentScope.create only, no master-key signals → no-master-key', () => {
    const hits: Hit[] = [{ file: 'src/a.ts', line: 1, type: 'agentscope-create', snippet: '...' }];
    const result = categorize(hits);
    expect(result.caseId).toBe('no-master-key');
  });

  it('env-reads + env-writes only → case #1 with write warning', () => {
    const hits: Hit[] = [
      { file: 'src/a.ts', line: 1, type: 'env-read', snippet: '...' },
      { file: 'src/a.ts', line: 2, type: 'env-write', snippet: '...' },
    ];
    const result = categorize(hits);
    expect(result.caseId).toBe('#1');
    expect(result.guidance.join(' ')).toContain('control-channel');
  });
});

// ─── Directory walking ────────────────────────────────────────────────────────

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

  it('only scans recognized source extensions', async () => {
    writeFile('src/a.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('src/b.tsx', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('src/c.mjs', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('src/d.cjs', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('src/e.js', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('src/f.jsx', 'process.env.AGENTS_MASTER_KEY;');
    // These should be ignored:
    writeFile('docs/README.md', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('config/settings.json', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('scripts/deploy.sh', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('.env.example', 'AGENTS_MASTER_KEY=00');

    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(6); // .ts, .tsx, .mjs, .cjs, .js, .jsx
  });

  it('walks nested directories', async () => {
    writeFile('packages/server/src/index.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('packages/server/src/lib/auth.ts', 'process.env.AGENTS_MASTER_KEY;');
    writeFile('packages/client/src/index.ts', 'process.env.AGENTS_MASTER_KEY;');

    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot, json: true }));
    const out = JSON.parse(stdout);
    expect(out.counts.envReads).toBe(3);
  });
});

// ─── Read-only invariant ──────────────────────────────────────────────────────

describe('migrate-check: read-only invariant', () => {
  it('never writes to the scanned tree', async () => {
    writeFile('src/server.ts', 'const k = process.env.AGENTS_MASTER_KEY;');
    writeFile('src/scope.ts', 'const s = AgentScope.create(c);');

    // Take a hash-like snapshot: file paths + contents + sizes.
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

// ─── Output format ────────────────────────────────────────────────────────────

describe('migrate-check: output format', () => {
  it('human-readable mode prints headline, guidance, and locations', async () => {
    writeFile('src/server.ts', 'const k = process.env.AGENTS_MASTER_KEY;');

    const { stdout } = await captureStdout(() => runMigrateCheck({ cwd: fixtureRoot }));

    expect(stdout).toContain('Scanning');
    expect(stdout).toContain('Found:');
    expect(stdout).toContain('1 process.env.AGENTS_MASTER_KEY read site(s)');
    expect(stdout).toContain('Case #1');
    expect(stdout).toContain('docs/migrations/byok.md');
    expect(stdout).toContain('read-only');
    expect(stdout).toContain('src/server.ts:');
  });

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
