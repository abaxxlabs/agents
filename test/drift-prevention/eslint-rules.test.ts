import { describe, it, expect } from 'vitest';
import { ESLint } from 'eslint';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = dirname(dirname(dirname(__filename)));

// Virtual paths exercise the real ESLint rules without creating files under src/.
describe('BYOK lint config: bootstrap/ and cli/ exempt, sql/ enforced', () => {
  const eslint = new ESLint({ cwd: REPO_ROOT });
  const bootstrapFixture = join(REPO_ROOT, 'src', 'bootstrap', '__byok-test-fixture.ts');
  const cliFixture = join(REPO_ROOT, 'src', 'cli', '__byok-test-fixture.ts');
  const sqlFixture = join(REPO_ROOT, 'src', 'sql', '__byok-test-fixture.ts');

  const violatingCode = [
    '// BYOK lint test fixture — do not commit',
    "const envVarName = 'AGENTS_MASTER_KEY';",
    'const key = process.env.AGENTS_MASTER_KEY;',
    'export {};',
  ].join('\n');

  async function lintVirtualFile(filePath: string): Promise<string[]> {
    const [result] = await eslint.lintText(violatingCode, { filePath });
    return result.messages
      .map(({ message }) => message)
      .filter((message) => message.includes('[BYOK]'));
  }

  it('src/bootstrap/ fixture: BYOK rules do NOT fire (exempt path)', async () => {
    const byokLines = await lintVirtualFile(bootstrapFixture);
    expect(byokLines).toHaveLength(0);
  });

  it('src/cli/ fixture: BYOK rules do NOT fire (exempt path)', async () => {
    const byokLines = await lintVirtualFile(cliFixture);
    expect(byokLines).toHaveLength(0);
  });

  it('src/sql/ fixture: BYOK rules DO fire for literal and env access', async () => {
    const byokLines = await lintVirtualFile(sqlFixture);
    expect(byokLines.length).toBeGreaterThanOrEqual(2);
  });
});
