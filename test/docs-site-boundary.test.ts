import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import { checkDocumentationBoundary, syncDocumentation } from '../scripts/sync-docs-site.mjs';

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function createFixture(manifest: Record<string, unknown>, sources: Record<string, string> = {}) {
  const rootDir = mkdtempSync(join(tmpdir(), 'docs-site-boundary-'));
  temporaryDirectories.push(rootDir);
  mkdirSync(join(rootDir, 'docs-site'), { recursive: true });
  mkdirSync(join(rootDir, 'docs'), { recursive: true });
  writeFileSync(join(rootDir, 'docs-site/content-manifest.json'), JSON.stringify(manifest));
  for (const [filePath, contents] of Object.entries(sources)) {
    const absolutePath = join(rootDir, filePath);
    mkdirSync(join(absolutePath, '..'), { recursive: true });
    writeFileSync(absolutePath, contents);
  }
  return rootDir;
}

const baseManifest = {
  version: 1,
  owner: 'Documentation maintainers',
  contentRoot: 'docs-site/content',
  siteOwnedPages: ['index.md'],
  imports: [{ source: 'docs/guides/public.md', target: 'guides/public.md' }],
};

describe('public documentation boundary', () => {
  it('validates the checked-in manifest and its exact source files', () => {
    const result = checkDocumentationBoundary();
    expect(result.imports.map(({ source, target }) => `${source} -> ${target}`)).toEqual([
      'docs/README.md -> repository-documentation.md',
      'docs/guides/security-and-storage-boundaries.md -> guides/security-and-storage-boundaries.md',
      'docs/migrations/byok.md -> migrations/byok.md',
      'docs/migrations/v0.9.10-rollback.md -> migrations/v0.9.10-rollback.md',
      'docs/migrations/v0.11.md -> migrations/v0.11.md',
    ]);
  });

  it.each([
    ['docs/internal/secret.md', 'internal documentation'],
    ['docs/../README.md', 'path traversal'],
    ['docs/guides/**', 'broad glob'],
  ])('rejects %s as an import source (%s)', (source) => {
    const rootDir = createFixture(
      { ...baseManifest, imports: [{ source, target: 'guides/public.md' }] },
      { 'docs/guides/public.md': '# public\n' },
    );
    expect(() => checkDocumentationBoundary(rootDir)).toThrow();
  });

  it('rejects missing sources and duplicate destinations', () => {
    const missingRoot = createFixture(baseManifest);
    expect(() => checkDocumentationBoundary(missingRoot)).toThrow(/does not exist/);

    const duplicateRoot = createFixture(
      {
        ...baseManifest,
        imports: [
          { source: 'docs/guides/one.md', target: 'guides/public.md' },
          { source: 'docs/guides/two.md', target: 'guides/public.md' },
        ],
      },
      { 'docs/guides/one.md': '# one\n', 'docs/guides/two.md': '# two\n' },
    );
    expect(() => checkDocumentationBoundary(duplicateRoot)).toThrow(/duplicate targets/);
  });

  it('syncs only allowlisted files and rejects stale generated files', () => {
    const rootDir = createFixture(baseManifest, { 'docs/guides/public.md': '# public\n' });
    const firstSync = syncDocumentation(rootDir);
    expect(firstSync).toEqual([{ source: 'docs/guides/public.md', target: 'guides/public.md' }]);
    expect(readFileSync(join(rootDir, 'docs-site/content/guides/public.md'), 'utf8')).toBe(
      '# public\n',
    );

    writeFileSync(
      join(rootDir, 'docs-site/content-manifest.json'),
      JSON.stringify({ ...baseManifest, imports: [] }),
    );
    expect(() => syncDocumentation(rootDir)).toThrow(/unmanaged public documentation file/);
    expect(existsSync(join(rootDir, 'docs-site/content/guides/public.md'))).toBe(true);
  });

  it('rejects unmanaged content and source or destination symlinks', () => {
    const rootDir = createFixture(baseManifest, { 'docs/guides/public.md': '# public\n' });
    mkdirSync(join(rootDir, 'docs-site/content'), { recursive: true });
    writeFileSync(join(rootDir, 'docs-site/content/unmanaged.md'), '# unmanaged\n');
    expect(() => syncDocumentation(rootDir)).toThrow(/unmanaged public documentation file/);

    const sourceRoot = createFixture(baseManifest, { 'docs/guides/public.md': '# public\n' });
    mkdirSync(join(sourceRoot, 'docs/internal'), { recursive: true });
    writeFileSync(join(sourceRoot, 'docs/internal/secret.md'), '# secret\n');
    rmSync(join(sourceRoot, 'docs/guides/public.md'));
    symlinkSync('../internal/secret.md', join(sourceRoot, 'docs/guides/public.md'));
    expect(() => checkDocumentationBoundary(sourceRoot)).toThrow(/symlinks/);

    const destinationRoot = createFixture(baseManifest, { 'docs/guides/public.md': '# public\n' });
    mkdirSync(join(destinationRoot, 'outside'), { recursive: true });
    mkdirSync(join(destinationRoot, 'docs-site/content'), { recursive: true });
    symlinkSync('../../outside', join(destinationRoot, 'docs-site/content/guides'));
    expect(() => syncDocumentation(destinationRoot)).toThrow(/symlinks/);
  });

  it('rejects symlinked public source directories, README sources, and site roots', () => {
    const sourceDirectoryRoot = createFixture(baseManifest, {
      'docs/guides/public.md': '# public\n',
      'docs/internal/secret.md': '# secret\n',
      'docs/internal/public.md': '# secret\n',
    });
    rmSync(join(sourceDirectoryRoot, 'docs/guides'), { recursive: true });
    symlinkSync('internal', join(sourceDirectoryRoot, 'docs/guides'));
    expect(() => checkDocumentationBoundary(sourceDirectoryRoot)).toThrow(/symlinks/);

    const readmeRoot = createFixture(
      {
        ...baseManifest,
        imports: [{ source: 'docs/README.md', target: 'reference/repository.md' }],
      },
      { 'docs/README.md': '# public\n', 'docs/internal/secret.md': '# secret\n' },
    );
    rmSync(join(readmeRoot, 'docs/README.md'));
    symlinkSync('internal/secret.md', join(readmeRoot, 'docs/README.md'));
    expect(() => checkDocumentationBoundary(readmeRoot)).toThrow(/symlinks/);

    const siteRoot = createFixture(baseManifest, { 'docs/guides/public.md': '# public\n' });
    const externalSite = join(siteRoot, 'external-site');
    renameSync(join(siteRoot, 'docs-site'), externalSite);
    symlinkSync('external-site', join(siteRoot, 'docs-site'));
    expect(() => checkDocumentationBoundary(siteRoot)).toThrow(/symlinks/);
    expect(() => syncDocumentation(siteRoot)).toThrow(/symlinks/);
  });
});
