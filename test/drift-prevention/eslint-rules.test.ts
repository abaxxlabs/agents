import { describe, it, expect } from 'vitest';
import { ESLint, Linter } from 'eslint';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = dirname(dirname(dirname(__filename)));

const byokRulesConfig: Linter.Config = {
  rules: {
    'no-restricted-syntax': [
      'error',
      {
        selector: "Literal[value='AGENTS_MASTER_KEY']",
        message: "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a string literal.",
      },
      {
        selector:
          "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
        message: "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a template literal.",
      },
      {
        selector:
          "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env']",
        message: '[BYOK D16] process.env property access requires a justification comment.',
      },
      // Computed process['env'] access closes the bracket-notation bypass.
      {
        selector:
          "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.value='env']",
        message: "[BYOK D16] process['env'] property access requires a justification comment.",
      },
    ],
  },
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
};

function makeLinter(): Linter {
  return new Linter({ configType: 'flat' });
}

function lintCode(code: string): Linter.LintMessage[] {
  return makeLinter().verify(code, byokRulesConfig);
}

function byokViolations(messages: Linter.LintMessage[]): string[] {
  return messages.filter((m) => m.ruleId === 'no-restricted-syntax').map((m) => m.message);
}

describe('Rule 1 — ban AGENTS_MASTER_KEY string literal', () => {
  it('fires on standalone single-quoted string literal', () => {
    const code = `const envVarName = 'AGENTS_MASTER_KEY';`;
    const violations = byokViolations(lintCode(code));
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations[0]).toContain('AGENTS_MASTER_KEY');
  });

  it('fires on standalone double-quoted string literal', () => {
    const code = `const x = "AGENTS_MASTER_KEY";`;
    const violations = byokViolations(lintCode(code));
    expect(violations.length).toBeGreaterThanOrEqual(1);
  });

  it('fires on template literal `AGENTS_MASTER_KEY`', () => {
    const code = 'const name = `AGENTS_MASTER_KEY`;';
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on bracket-notation process.env["AGENTS_MASTER_KEY"] (Literal + process.env)', () => {
    const code = `const key = process.env['AGENTS_MASTER_KEY'];`;
    const violations = byokViolations(lintCode(code));
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('does not fire on a different string literal', () => {
    const code = `const x = 'SOME_OTHER_VAR';`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on a string that partially contains the key name', () => {
    const code = `const x = 'MY_AGENTS_MASTER_KEY_EXTRA';`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on dot-notation process.env.AGENTS_MASTER_KEY (no Literal node)', () => {
    const code = `const v = process.env.AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintCode(code));
    const rule1Fires = violations.some((m) =>
      m.includes("Do not reference 'AGENTS_MASTER_KEY' as a string literal"),
    );
    expect(rule1Fires).toBe(false);
    expect(violations.some((m) => m.includes('process.env property access'))).toBe(true);
  });
});

describe('Rule 2 — process.env property access', () => {
  it('fires on process.env.DATABASE_URL (dot notation)', () => {
    const code = `const url = process.env.DATABASE_URL;`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('process.env property access'))).toBe(true);
  });

  it('fires on process.env.NODE_ENV', () => {
    const code = `const env = process.env.NODE_ENV;`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('process.env'))).toBe(true);
  });

  it('fires on process.env.AGENTS_MASTER_KEY (dot notation)', () => {
    const code = `const key = process.env.AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('process.env property access'))).toBe(true);
  });

  it('fires on conditional process.env access', () => {
    const code = `const v = process.env.CI === 'true' ? 'ci' : 'local';`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('process.env'))).toBe(true);
  });

  it('fires inside an if condition', () => {
    const code = `if (process.env.AGENTS_DEV_MODE === 'true') { console.log('dev'); }`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('process.env'))).toBe(true);
  });

  it("fires on process['env'].FOO bracket-bypass form (Rule 2b)", () => {
    const code = `const v = process['env'].DATABASE_URL;`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes("process['env']"))).toBe(true);
  });

  it("fires on process['env'].AGENTS_MASTER_KEY bracket-bypass form (Rule 2b)", () => {
    const code = `const k = process['env'].AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes("process['env']"))).toBe(true);
  });

  it("fires on process['env']['FOO'] fully-bracketed form", () => {
    const code = `const k = process['env']['DATABASE_URL'];`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes("process['env']"))).toBe(true);
  });

  it('does not fire when eslint-disable-next-line with-justification comment is present', () => {
    const code = [
      '// eslint-disable-next-line no-restricted-syntax -- with-justification: legacy env read',
      'const v = process.env.AGENTS_MASTER_KEY;',
    ].join('\n');
    const violations = byokViolations(lintCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does not fire on non-env member expressions (obj.config.value)', () => {
    const code = `const x = obj.config.value;`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on process.argv (property name is not "env")', () => {
    const code = `const args = process.argv;`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on process.cwd() call (not an env access)', () => {
    const code = `const dir = process.cwd();`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on process.env spread (two-level chain, not a property access)', () => {
    // Intentional: spreading process.env is not a directed property read.
    const code = `const env = { ...process.env };`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });
});

// Virtual paths avoid mutating src/.
describe('File-scope: bootstrap/ and cli/ exempt, sql/ enforced', () => {
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

  it('src/sql/ fixture: BYOK rules DO fire for both Rule 1 and Rule 2', async () => {
    const byokLines = await lintVirtualFile(sqlFixture);
    expect(byokLines.length).toBeGreaterThanOrEqual(2);
  });
});

const packageByokRulesConfig: Linter.Config = {
  rules: {
    'no-restricted-syntax': [
      'error',
      {
        selector: "Literal[value='AGENTS_MASTER_KEY']",
        message:
          "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a string literal in package source.",
      },
      {
        selector:
          "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
        message:
          "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a template literal in package source.",
      },
      {
        selector:
          "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env'][property.name='AGENTS_MASTER_KEY']",
        message: '[BYOK D16] Do not read process.env.AGENTS_MASTER_KEY directly in package source.',
      },
      // Intentionally broad: also flags object literals and aliased properties.
      {
        selector: "Property[key.name='AGENTS_MASTER_KEY']",
        message:
          '[BYOK D16] Do not destructure AGENTS_MASTER_KEY from process.env (or define it as a property name) in package source.',
      },
    ],
  },
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
};

function lintPackageCode(code: string): Linter.LintMessage[] {
  return makeLinter().verify(code, packageByokRulesConfig);
}

describe('Package-scope Rule 2 — narrowed to AGENTS_MASTER_KEY only', () => {
  it('fires on process.env.AGENTS_MASTER_KEY (the only banned env var in package scope)', () => {
    const code = `const k = process.env.AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('process.env.AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('does NOT fire on process.env.DATABASE_URL (server may read it)', () => {
    const code = `const url = process.env.DATABASE_URL;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.OIDC_ALLOWED_ISSUERS (server may read it)', () => {
    const code = `const issuers = process.env.OIDC_ALLOWED_ISSUERS?.split(',');`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.SESSION_STORE / REVOCATION_STORE', () => {
    const code = [
      `const store = process.env.SESSION_STORE ?? 'memory';`,
      `const rev = process.env.REVOCATION_STORE ?? 'auto';`,
    ].join('\n');
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.ADMIN_API_KEY (server reads it)', () => {
    const code = `const adminKey = process.env.ADMIN_API_KEY;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });
});

describe('Package-scope Rule 3 — destructure closure', () => {
  it('fires on const { AGENTS_MASTER_KEY } = process.env', () => {
    const code = `const { AGENTS_MASTER_KEY } = process.env;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on const { AGENTS_MASTER_KEY, DATABASE_URL } = process.env (mixed destructure)', () => {
    const code = `const { AGENTS_MASTER_KEY, DATABASE_URL } = process.env;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
    expect(violations.filter((m) => m.includes('Do not destructure'))).toHaveLength(1);
  });

  it('fires on aliased destructure: const { AGENTS_MASTER_KEY: alias } = process.env', () => {
    const code = `const { AGENTS_MASTER_KEY: alias } = process.env;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on object-literal property (known false positive, accepted by design)', () => {
    const code = `const obj = { AGENTS_MASTER_KEY: 'foo' };`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('does NOT fire on const { DATABASE_URL } = process.env', () => {
    const code = `const { DATABASE_URL } = process.env;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on a renamed property whose source key is not AGENTS_MASTER_KEY', () => {
    const code = `const { DATABASE_URL: AGENTS_MASTER_KEY_LIKE_THIS } = process.env;`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on a string-keyed property (key is Literal not Identifier)', () => {
    const code = `const obj = { 'NOT_AGENTS_MASTER_KEY': 'foo' };`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations).toHaveLength(0);
  });
});

describe('Package-scope Rule 1 — literal/template (same as lib-core)', () => {
  it('fires on standalone string literal', () => {
    const code = `const name = 'AGENTS_MASTER_KEY';`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes("'AGENTS_MASTER_KEY' as a string literal"))).toBe(
      true,
    );
  });

  it("fires on bracket-access process.env['AGENTS_MASTER_KEY']", () => {
    const code = `const k = process.env['AGENTS_MASTER_KEY'];`;
    const violations = byokViolations(lintPackageCode(code));
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });
});
