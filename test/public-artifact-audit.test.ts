import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  auditPackageFiles,
  auditPublicRepoFiles,
  defaultPublicRepoCandidatePaths,
} from '../scripts/audit-public-artifacts.mjs';

function violationReasons(result: {
  violations: Array<{ path: string; reason: string; line?: number }>;
}) {
  return result.violations.map((violation) => {
    const line = violation.line === undefined ? '' : `:${violation.line}`;
    return `${violation.path}${line}: ${violation.reason}`;
  });
}

function writeFixture(rootDir: string, filePath: string, contents: string) {
  mkdirSync(join(rootDir, dirname(filePath)), { recursive: true });
  writeFileSync(join(rootDir, filePath), contents);
}

function runAuditCli(args: string[], input?: string) {
  return spawnSync(process.execPath, ['scripts/audit-public-artifacts.mjs', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    input,
  });
}

describe('public artifact audit policy', () => {
  it('allows only approved npm package files', () => {
    const result = auditPackageFiles(
      [
        'package.json',
        'README.md',
        'LICENSE',
        'dist/index.js',
        'dist/cjs/index.js',
        'dist/cjs/package.json',
      ],
      { scanContents: false },
    );

    expect(result.ok).toBe(true);
  });

  it('rejects package files outside the npm allowlist', () => {
    const result = auditPackageFiles(['package.json', 'CLAUDE.md', 'src/index.ts']);

    expect(result.ok).toBe(false);
    expect(violationReasons(result)).toEqual([
      'CLAUDE.md: not in artifact allowlist',
      'src/index.ts: not in artifact allowlist',
    ]);
  });

  it('rejects credential-shaped files inside package-allowed directories', () => {
    const result = auditPackageFiles(['dist/server.key', 'vendor/id-sdk-mcp/test.pem'], {
      scanContents: false,
    });

    expect(result.ok).toBe(false);
    expect(violationReasons(result)).toEqual([
      'dist/server.key: forbidden path (**/*.key)',
      'vendor/id-sdk-mcp/test.pem: forbidden path (**/*.pem)',
    ]);
  });

  it('allows approved public repo release files', () => {
    const result = auditPublicRepoFiles(
      [
        'README.md',
        'LICENSE',
        'package.json',
        'src/index.ts',
        'packages/server/src/index.ts',
        'packages/create-agents/template/README.md',
        'docs/migration-byok.md',
        'demo/showcase/src/server.ts',
        'demo/showcase/scripts/launch-smoke.mjs',
        'scripts/audit-public-artifacts.mjs',
      ],
      { scanContents: false },
    );

    expect(result.ok).toBe(true);
  });

  it('keeps the audit script self-scan allowlisted to the blocked-term definition lines', () => {
    const result = auditPublicRepoFiles(['scripts/audit-public-artifacts.mjs']);

    expect(result.ok).toBe(true);
  });

  it('rejects forbidden public repo paths before allowlist checks', () => {
    const result = auditPublicRepoFiles(
      [
        'README.md',
        '.claude/settings.local.json',
        '.mcp.json',
        'docs/plan-v0.11.1-prelanding-fixes.md',
        'docs/support-runbook-v0.9.10.0.md',
        'demo/hackathon/findings/matias/01-createagent-missing-returning.md',
        '.env.local',
        'client_secret.json',
      ],
      { scanContents: false },
    );

    expect(result.ok).toBe(false);
    expect(violationReasons(result)).toEqual([
      '.claude/settings.local.json: forbidden path (.claude/**)',
      '.mcp.json: forbidden path (.mcp.json)',
      'docs/plan-v0.11.1-prelanding-fixes.md: forbidden path (docs/plan-*.md)',
      'docs/support-runbook-v0.9.10.0.md: forbidden path (docs/support-runbook-*.md)',
      'demo/hackathon/findings/matias/01-createagent-missing-returning.md: forbidden path (demo/hackathon/findings/**)',
      '.env.local: forbidden path (**/.env.*)',
      'client_secret.json: forbidden path (**/client_secret.json)',
    ]);
  });

  it('rejects high-confidence secret content without echoing the secret', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-'));
    const token = `github_pat_${'a'.repeat(40)}`;
    const databaseUrl = 'postgresql://' + 'deploy:s3cr3t@db.prod.example.net:5432/agents';
    writeFileSync(
      join(rootDir, 'README.md'),
      [
        `token: ${token}`,
        'aws_session=' + 'ASIA' + '1234567890ABCDEF',
        '"private_' + 'key_id": "abc123def456ghi789"',
        `DATABASE_URL=${databaseUrl}`,
      ].join('\n'),
    );

    const result = auditPublicRepoFiles(['README.md'], { rootDir });

    expect(result.ok).toBe(false);
    expect(result.violations).toEqual(
      expect.arrayContaining([
        {
          path: 'README.md',
          reason: 'contains high-confidence secret pattern: GitHub token',
        },
        {
          path: 'README.md',
          reason: 'contains high-confidence secret pattern: AWS temporary access key id',
        },
        {
          path: 'README.md',
          reason: 'contains high-confidence secret pattern: GCP service account key metadata',
        },
        {
          path: 'README.md',
          reason: 'contains high-confidence secret pattern: database URL with embedded password',
        },
      ]),
    );
    expect(JSON.stringify(result.violations)).not.toContain(token);
    expect(JSON.stringify(result.violations)).not.toContain(databaseUrl);
  });

  it('rejects blocked internal-history terms in public package source with path, line, and term', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-blocked-package-'));
    writeFixture(
      rootDir,
      'README.md',
      ['# Clean title', 'This public package source should not mention Phase 1 work.'].join('\n'),
    );

    const result = auditPackageFiles(['README.md'], { rootDir });

    expect(result.ok).toBe(false);
    expect(result.violations).toEqual([
      {
        path: 'README.md',
        line: 2,
        term: 'Phase',
        reason: 'contains blocked release term "Phase" (temporal/internal delivery history)',
      },
    ]);
  });

  it('rejects blocked strategy terms in showcase demo source with path, line, and term', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-blocked-showcase-'));
    writeFixture(
      rootDir,
      'demo/showcase/src/server.ts',
      [
        'export const headline = "Scoped agent access";',
        'export const copy = "No commercial teaser here";',
      ].join('\n'),
    );

    const result = auditPublicRepoFiles(['demo/showcase/src/server.ts'], { rootDir });

    expect(result.ok).toBe(false);
    expect(result.violations).toEqual([
      {
        path: 'demo/showcase/src/server.ts',
        line: 2,
        term: 'commercial',
        reason: 'contains blocked release term "commercial" (strategy/commercial positioning)',
      },
    ]);
  });

  it('supports narrow blocked-term allowlist entries with a documented reason', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-blocked-allowlist-'));
    writeFixture(rootDir, 'README.md', 'This paid fixture is intentionally allowlisted.\n');

    const result = auditPackageFiles(['README.md'], {
      rootDir,
      blockedTermAllowlist: [
        {
          path: 'README.md',
          term: 'paid',
          linePattern: '^This paid fixture is intentionally allowlisted\\.$',
          reason: 'Documents a literal blocked-term fixture for the audit allowlist test.',
        },
      ],
    });

    expect(result.ok).toBe(true);
  });

  it('rejects broad blocked-term allowlist entries without a term or line pattern', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-broad-allowlist-'));
    writeFixture(
      rootDir,
      'README.md',
      'This paid line should not be hidden by a file-only allowlist.\n',
    );

    expect(() =>
      auditPackageFiles(['README.md'], {
        rootDir,
        blockedTermAllowlist: [
          {
            path: 'README.md',
            reason: 'This file-only exception is too broad for public release artifacts.',
          },
        ],
      }),
    ).toThrow('must include a term or linePattern constraint');
  });

  it('does not flag localhost database examples as leaked credentials', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-localhost-'));
    writeFileSync(
      join(rootDir, 'README.md'),
      'DATABASE_URL=postgresql://postgres:postgres@localhost:54322/postgres\n',
    );

    const result = auditPublicRepoFiles(['README.md'], { rootDir });

    expect(result.ok).toBe(true);
  });

  it('fails explicitly when text files exceed the content scan size limit', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-large-'));
    mkdirSync(join(rootDir, 'docs'));
    writeFileSync(join(rootDir, 'docs', 'migration-large.md'), 'x'.repeat(1024 * 1024 + 1));

    const result = auditPublicRepoFiles(['docs/migration-large.md'], { rootDir });

    expect(result.ok).toBe(false);
    expect(result.violations).toEqual([
      {
        path: 'docs/migration-large.md',
        reason: 'exceeds text content scan size limit (1048576 bytes)',
      },
    ]);
  });

  it('audits forbidden paths discovered from an explicit public repo root', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-git-'));
    execFileSync('git', ['init'], { cwd: rootDir, stdio: 'ignore' });
    writeFileSync(join(rootDir, 'README.md'), '# Public README\n');
    writeFileSync(join(rootDir, '.mcp.json'), '{}\n');
    execFileSync('git', ['add', 'README.md'], { cwd: rootDir, stdio: 'ignore' });

    const candidates = defaultPublicRepoCandidatePaths(rootDir);

    expect(candidates).toEqual(expect.arrayContaining(['README.md', '.mcp.json']));
    const result = auditPublicRepoFiles(candidates, { rootDir });
    expect(result.ok).toBe(false);
    expect(violationReasons(result)).toContain('.mcp.json: forbidden path (.mcp.json)');
  });

  it('requires an explicit assembled public repo root for the public-repo CLI', () => {
    const result = runAuditCli(['public-repo', '--public-list', '-'], 'README.md\n');

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('public-repo audit requires --public-root');
    expect(result.stderr).toContain('Usage:');
  });

  it('refuses to use the internal checkout as the public-repo CLI target', () => {
    const result = runAuditCli(
      ['public-repo', '--public-root', '.', '--public-list', '-'],
      'README.md\n',
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refusing to use the internal repository root');
  });

  it('audits a provided candidate list against the explicit public repo root', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-cli-'));
    const listPath = join(rootDir, 'public-repo-files.txt');
    writeFileSync(join(rootDir, 'README.md'), '# Public README\n');
    writeFileSync(join(rootDir, '.mcp.json'), '{}\n');
    writeFileSync(listPath, 'README.md\n.mcp.json\n');

    const result = runAuditCli([
      'public-repo',
      '--public-root',
      rootDir,
      '--public-list',
      listPath,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('- .mcp.json: forbidden path (.mcp.json)');
  });

  it('keeps secret scanning enabled in security-only CLI mode', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-security-only-'));
    const listPath = join(rootDir, 'public-repo-files.txt');
    writeFileSync(join(rootDir, 'README.md'), '-----BEGIN ' + 'PRIVATE KEY-----\nfixture\n');
    writeFileSync(listPath, 'README.md\n');

    const result = runAuditCli([
      'public-repo',
      '--public-root',
      rootDir,
      '--public-list',
      listPath,
      '--security-only',
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('contains high-confidence secret pattern: private key block');
  });

  it('does not apply editorial term checks in security-only CLI mode', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-security-only-'));
    const listPath = join(rootDir, 'public-repo-files.txt');
    writeFileSync(join(rootDir, 'README.md'), 'Public migration Phase 1\n');
    writeFileSync(listPath, 'README.md\n');

    const result = runAuditCli([
      'public-repo',
      '--public-root',
      rootDir,
      '--public-list',
      listPath,
      '--security-only',
    ]);

    expect(result.status).toBe(0);
  });

  it('fails when provided CLI candidates are missing from the explicit public repo root', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-cli-missing-'));
    const listPath = join(rootDir, 'public-repo-files.txt');
    writeFileSync(listPath, 'README.md\n');

    const result = runAuditCli([
      'public-repo',
      '--public-root',
      rootDir,
      '--public-list',
      listPath,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('- README.md: candidate file does not exist under audit root');
  });

  it('audits a generated git candidate list against the explicit public repo root', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'artifact-audit-cli-git-'));
    execFileSync('git', ['init'], { cwd: rootDir, stdio: 'ignore' });
    writeFileSync(join(rootDir, 'README.md'), '# Public README\n');
    execFileSync('git', ['add', 'README.md'], { cwd: rootDir, stdio: 'ignore' });

    const result = runAuditCli(['public-repo', '--public-root', rootDir, '--public-list', 'git']);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('Public repo artifact audit passed: 1 files');
  });
});
