import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const root = join(fileURLToPath(new URL('..', import.meta.url)));
const quickStartPath = join(root, 'docs/guides/quick-start.md');

function readSdkDirectExample(): string {
  const markdown = readFileSync(quickStartPath, 'utf8');
  const match = markdown.match(/## Run the SDK-direct flow\n\n```typescript\n([\s\S]*?)\n```/);
  if (!match) throw new Error('SDK-direct example is missing from quick-start.md');
  return match[1];
}

describe('SDK-direct documentation example', () => {
  it('uses the public imports and type-checks against the package source', () => {
    const example = readSdkDirectExample();
    expect(example).toContain("import { AgentScope } from '@abaxxlabs/agents/sql';");
    expect(example).toContain(
      "import { asMasterKey, createPresentation } from '@abaxxlabs/agents';",
    );
    expect(example).not.toMatch(/from ['"]#/);
    expect(example).toContain('requirePresentation: true');
    expect(example).toContain('audience: scope.verifierDid');

    const tsconfig = JSON.parse(readFileSync(join(root, 'tsconfig.json'), 'utf8')) as {
      compilerOptions: { paths: ts.CompilerOptions['paths'] };
    };
    const temporaryRoot = mkdtempSync(join(tmpdir(), 'agents-doc-example-'));
    const sourcePath = join(temporaryRoot, 'quick-start.ts');
    writeFileSync(sourcePath, example);

    try {
      const program = ts.createProgram([sourcePath], {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        types: ['node'],
        baseUrl: root,
        paths: tsconfig.compilerOptions.paths,
        noEmit: true,
      });
      const diagnostics = ts.getPreEmitDiagnostics(program);
      expect(
        diagnostics.map((diagnostic) =>
          ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'),
        ),
      ).toEqual([]);
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });
});
