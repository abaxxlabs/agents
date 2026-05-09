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

/**
 * ESLint rule tests — BYOK trust-boundary drift prevention.
 *
 * Verifies that the two BYOK ESLint rules in eslint.config.js behave as
 * specified. Both rules are implemented as `no-restricted-syntax` selectors in
 * a single config block, scoped to `src/**` (excluding `src/bootstrap/` and
 * `src/cli/`).
 *
 * Layer 1 — Programmatic Linter API: tests selector logic directly using
 * ESLint's `Linter` class with inline config. Fast, deterministic, no
 * subprocess overhead.
 *
 * Layer 2 — CLI integration: spawns `eslint` against temporary fixture files
 * placed inside src/ to verify that `ignores` patterns correctly exempt
 * `src/bootstrap/` and `src/cli/` while enforcing rules in `src/sql/`.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Linter } from 'eslint';
import { spawnSync } from 'child_process';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// ESM-portable repo root: test lives at <repo>/test/drift-prevention/eslint-rules.test.ts,
// so repo root is two levels up.
const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = dirname(dirname(dirname(__filename)));

// ──────────────────────────────────────────────────────────────────────────────
// Shared configuration for programmatic Linter API tests
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Flat-config object that activates both BYOK rules at 'error' severity.
 * Mirrors the no-restricted-syntax entries from eslint.config.js.
 */
const byokRulesConfig: Linter.Config = {
  rules: {
    'no-restricted-syntax': [
      'error',
      // Rule 1a: ban 'AGENTS_MASTER_KEY' string literal
      {
        selector: "Literal[value='AGENTS_MASTER_KEY']",
        message: "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a string literal.",
      },
      // Rule 1b: ban `AGENTS_MASTER_KEY` template literal
      {
        selector:
          "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
        message: "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a template literal.",
      },
      // Rule 2a: ban process.env.FOO dot-notation property access
      {
        selector:
          "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env']",
        message: '[BYOK D16] process.env property access requires a justification comment.',
      },
      // Rule 2b: ban process['env'].FOO bracket-notation bypass — without this,
      // an obfuscated computed access would silently pass while dot-notation is blocked.
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

/** Returns only no-restricted-syntax violation messages. */
function byokViolations(messages: Linter.LintMessage[]): string[] {
  return messages.filter((m) => m.ruleId === 'no-restricted-syntax').map((m) => m.message);
}

// ──────────────────────────────────────────────────────────────────────────────
// Rule 1 — ban 'AGENTS_MASTER_KEY' string literal
// ──────────────────────────────────────────────────────────────────────────────

describe('Rule 1 — ban AGENTS_MASTER_KEY string literal', () => {
  // ── Positive cases (rule SHOULD fire) ────────────────────────────────────

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
    // A TemplateLiteral with no expressions and a single quasis cooked to
    // 'AGENTS_MASTER_KEY' matches Rule 1b.
    const code = 'const name = `AGENTS_MASTER_KEY`;';
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on bracket-notation process.env["AGENTS_MASTER_KEY"] (Literal + process.env)', () => {
    // This fires BOTH Rule 1a (the string literal 'AGENTS_MASTER_KEY')
    // AND Rule 2 (process.env.* chain via computed bracket access).
    const code = `const key = process.env['AGENTS_MASTER_KEY'];`;
    const violations = byokViolations(lintCode(code));
    // At minimum Rule 1 fires; Rule 2 also fires for the process.env access
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });

  // ── Negative cases (rule should NOT fire) ────────────────────────────────

  it('does not fire on a different string literal', () => {
    const code = `const x = 'SOME_OTHER_VAR';`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on a string that partially contains the key name', () => {
    // The selector uses exact value match (value='AGENTS_MASTER_KEY'), so
    // superset strings must not trigger it.
    const code = `const x = 'MY_AGENTS_MASTER_KEY_EXTRA';`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on dot-notation process.env.AGENTS_MASTER_KEY (no Literal node)', () => {
    // Dot notation uses an Identifier AST node for the property name, not a
    // Literal. Rule 1 only targets Literal nodes. Rule 2 fires instead.
    const code = `const v = process.env.AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintCode(code));
    // Rule 2 fires (process.env property access), but Rule 1 must NOT fire.
    const rule1Fires = violations.some((m) =>
      m.includes("Do not reference 'AGENTS_MASTER_KEY' as a string literal"),
    );
    expect(rule1Fires).toBe(false);
    // Rule 2 should fire (confirming Rule 2 covers the dot-notation case).
    expect(violations.some((m) => m.includes('process.env property access'))).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Rule 2 — process.env property access requires justification
// ──────────────────────────────────────────────────────────────────────────────

describe('Rule 2 — process.env property access', () => {
  // ── Positive cases (rule SHOULD fire) ────────────────────────────────────

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

  // ── Rule 2b: bracket-notation bypass closure ─────────────────────────────

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
    // Inner bracket triggers Rule 2b (process['env'].*); outer bracket does
    // not need a separate selector — Rule 2b matches the outer MemberExpression
    // whose object is process['env'] regardless of how the outer property is
    // accessed.
    const code = `const k = process['env']['DATABASE_URL'];`;
    const violations = byokViolations(lintCode(code));
    expect(violations.some((m) => m.includes("process['env']"))).toBe(true);
  });

  // ── Negative cases (rule should NOT fire) ────────────────────────────────

  it('does not fire when eslint-disable-next-line with-justification comment is present', () => {
    // The ESLint programmatic Linter honours inline disable comments.
    // This verifies the disable mechanism works for the with-justification pattern.
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
    // The Rule 2 selector requires object.property.name='env'. process.argv
    // has property.name='argv', so it must not fire.
    const code = `const args = process.argv;`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on process.cwd() call (not an env access)', () => {
    const code = `const dir = process.cwd();`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });

  it('does not fire on process.env spread (two-level chain, not a property access)', () => {
    // {…process.env} spreads the process.env object itself — the AST node is
    // MemberExpression { object: Identifier(process), property: Identifier(env) }.
    // The Rule 2 selector targets the OUTER MemberExpression of a three-level
    // chain (process.env.FOO), so the two-level spread does NOT match.
    // This is by design: spread access is not a directed property read of a
    // specific env var and is considered a lower-risk pattern.
    const code = `const env = { ...process.env };`;
    expect(byokViolations(lintCode(code))).toHaveLength(0);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// File-scope integration: bootstrap/ and cli/ are exempt; sql/ is not
// ──────────────────────────────────────────────────────────────────────────────
//
// Spawns `eslint` against temporary fixture files inside the actual src/ tree
// so eslint.config.js resolves its `files` + `ignores` globs against real paths.

describe('File-scope: bootstrap/ and cli/ exempt, sql/ enforced', () => {
  // Fixture paths sit inside the real src/ tree under existing exempt/non-exempt dirs.
  // Files use a '__byok-test-' prefix to make cleanup safe and unambiguous.
  const bootstrapFixture = join(REPO_ROOT, 'src', 'bootstrap', '__byok-test-fixture.ts');
  const cliFixture = join(REPO_ROOT, 'src', 'cli', '__byok-test-fixture.ts');
  const sqlFixture = join(REPO_ROOT, 'src', 'sql', '__byok-test-fixture.ts');

  // Fixture source: violates both rules — contains 'AGENTS_MASTER_KEY' literal
  // and process.env.AGENTS_MASTER_KEY property access.
  const violatingCode = [
    '// BYOK lint test fixture — do not commit',
    "const envVarName = 'AGENTS_MASTER_KEY';",
    'const key = process.env.AGENTS_MASTER_KEY;',
    'export {};',
  ].join('\n');

  beforeAll(() => {
    mkdirSync(join(REPO_ROOT, 'src', 'sql'), { recursive: true });
    writeFileSync(bootstrapFixture, violatingCode, 'utf8');
    writeFileSync(cliFixture, violatingCode, 'utf8');
    writeFileSync(sqlFixture, violatingCode, 'utf8');
  });

  afterAll(() => {
    // Clean up fixture files. rmSync with force:true won't error if already gone.
    rmSync(bootstrapFixture, { force: true });
    rmSync(cliFixture, { force: true });
    rmSync(sqlFixture, { force: true });
  });

  it('src/bootstrap/ fixture: BYOK rules do NOT fire (exempt path)', () => {
    const result = spawnSync(
      './node_modules/.bin/eslint',
      ['--no-warn-ignored', bootstrapFixture],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    );
    const output = result.stdout + result.stderr;
    const byokLines = output.split('\n').filter((l) => l.includes('[BYOK]'));
    expect(byokLines).toHaveLength(0);
  });

  it('src/cli/ fixture: BYOK rules do NOT fire (exempt path)', () => {
    const result = spawnSync('./node_modules/.bin/eslint', ['--no-warn-ignored', cliFixture], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    const output = result.stdout + result.stderr;
    const byokLines = output.split('\n').filter((l) => l.includes('[BYOK]'));
    expect(byokLines).toHaveLength(0);
  });

  it('src/sql/ fixture: BYOK rules DO fire for both Rule 1 and Rule 2', () => {
    const result = spawnSync('./node_modules/.bin/eslint', ['--no-warn-ignored', sqlFixture], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    const output = result.stdout + result.stderr;
    const byokLines = output.split('\n').filter((l) => l.includes('[BYOK]'));
    // Rule 1 fires on 'AGENTS_MASTER_KEY' literal (line 2 of fixture)
    // Rule 2 fires on process.env.AGENTS_MASTER_KEY (line 3 of fixture)
    expect(byokLines.length).toBeGreaterThanOrEqual(2);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Server-scope rules — packages/server/src/**/*.ts
// ──────────────────────────────────────────────────────────────────────────────
//
// The server scope has a DIFFERENT rule set from lib-core because packages/server
// legitimately reads many env vars (DATABASE_URL, OIDC_*, SESSION_STORE, ...).
// The server-scope rules narrow specifically to AGENTS_MASTER_KEY:
//
//   Rule 1 (literal):       ban 'AGENTS_MASTER_KEY' / `AGENTS_MASTER_KEY`
//   Rule 2 (server-narrow): ban process.env.AGENTS_MASTER_KEY ONLY
//   Rule 3 (destructure):   ban Property[key.name='AGENTS_MASTER_KEY']
//                           catches `const { AGENTS_MASTER_KEY } = process.env;`

const serverByokRulesConfig: Linter.Config = {
  rules: {
    'no-restricted-syntax': [
      'error',
      // Rule 1 — ban 'AGENTS_MASTER_KEY' literal
      {
        selector: "Literal[value='AGENTS_MASTER_KEY']",
        message:
          "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a string literal in packages/server/src/.",
      },
      // Rule 1b — ban template literal
      {
        selector:
          "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
        message:
          "[BYOK D16] Do not reference 'AGENTS_MASTER_KEY' as a template literal in packages/server/src/.",
      },
      // Rule 2 — server-narrow: ban ONLY process.env.AGENTS_MASTER_KEY (dot notation).
      // Other env reads remain allowed in server scope.
      {
        selector:
          "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env'][property.name='AGENTS_MASTER_KEY']",
        message:
          '[BYOK D16] Do not read process.env.AGENTS_MASTER_KEY directly in packages/server/src/.',
      },
      // Rule 3 — destructure / object-property closure.
      // Selector matches Property nodes with key=Identifier name='AGENTS_MASTER_KEY'.
      {
        selector: "Property[key.name='AGENTS_MASTER_KEY']",
        message:
          '[BYOK D16] Do not destructure AGENTS_MASTER_KEY from process.env (or define it as a property name) in packages/server/src/.',
      },
    ],
  },
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
};

function lintServerCode(code: string): Linter.LintMessage[] {
  return makeLinter().verify(code, serverByokRulesConfig);
}

describe('Server-scope Rule 2 — narrowed to AGENTS_MASTER_KEY only', () => {
  // ── Positive (rule 2 fires only on AGENTS_MASTER_KEY) ────────────────────

  it('fires on process.env.AGENTS_MASTER_KEY (the only banned env var in server scope)', () => {
    const code = `const k = process.env.AGENTS_MASTER_KEY;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('process.env.AGENTS_MASTER_KEY'))).toBe(true);
  });

  // ── Negative (rule 2 does NOT fire on other env vars in server scope) ────
  // Unlike lib-core, the server may read DATABASE_URL, OIDC_*, SESSION_STORE, etc.

  it('does NOT fire on process.env.DATABASE_URL (server may read it)', () => {
    const code = `const url = process.env.DATABASE_URL;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.OIDC_ALLOWED_ISSUERS (server may read it)', () => {
    const code = `const issuers = process.env.OIDC_ALLOWED_ISSUERS?.split(',');`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.SESSION_STORE / REVOCATION_STORE', () => {
    const code = [
      `const store = process.env.SESSION_STORE ?? 'memory';`,
      `const rev = process.env.REVOCATION_STORE ?? 'auto';`,
    ].join('\n');
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on process.env.ADMIN_API_KEY (server reads it)', () => {
    const code = `const adminKey = process.env.ADMIN_API_KEY;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });
});

describe('Server-scope Rule 3 — destructure closure', () => {
  // ── Positive (destructure pattern fires Rule 3) ──────────────────────────

  it('fires on const { AGENTS_MASTER_KEY } = process.env (the C1 bypass)', () => {
    const code = `const { AGENTS_MASTER_KEY } = process.env;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on const { AGENTS_MASTER_KEY, DATABASE_URL } = process.env (mixed destructure)', () => {
    // Even when destructuring multiple vars, the AGENTS_MASTER_KEY property
    // alone fires Rule 3. DATABASE_URL is fine and silent.
    const code = `const { AGENTS_MASTER_KEY, DATABASE_URL } = process.env;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
    // Only one violation (the AGENTS_MASTER_KEY property), not two.
    expect(violations.filter((m) => m.includes('Do not destructure'))).toHaveLength(1);
  });

  it('fires on aliased destructure: const { AGENTS_MASTER_KEY: alias } = process.env', () => {
    // The Property node has key.name='AGENTS_MASTER_KEY' even when aliased,
    // so the rule fires regardless of the alias name. Aliasing is not an
    // escape hatch.
    const code = `const { AGENTS_MASTER_KEY: alias } = process.env;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  it('fires on object-literal property (known false positive, accepted by design)', () => {
    // Constructing such a literal in server code would itself be a regression worth
    // flagging. Test codifies the accepted behavior so a future refactor can't
    // silently tighten the selector and break this contract.
    const code = `const obj = { AGENTS_MASTER_KEY: 'foo' };`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('Do not destructure AGENTS_MASTER_KEY'))).toBe(true);
  });

  // ── Negative (destructure pattern does NOT fire on other names) ──────────

  it('does NOT fire on const { DATABASE_URL } = process.env', () => {
    const code = `const { DATABASE_URL } = process.env;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on a renamed property whose source key is not AGENTS_MASTER_KEY', () => {
    // The selector matches on key.name (the LHS of the property). Renaming
    // a different property TO AGENTS_MASTER_KEY would fire Rule 3 (correctly
    // — that is the same regression worth flagging). But renaming a different
    // property AWAY from anything matching AGENTS_MASTER_KEY does not fire.
    const code = `const { DATABASE_URL: AGENTS_MASTER_KEY_LIKE_THIS } = process.env;`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });

  it('does NOT fire on a string-keyed property (key is Literal not Identifier)', () => {
    // The selector requires key.name (Identifier with .name). A string-keyed
    // property has key.value, not key.name. This is a corner case — code that
    // uses string-keyed property names with this exact value would be unusual
    // — but the test pins the selector behavior.
    const code = `const obj = { 'NOT_AGENTS_MASTER_KEY': 'foo' };`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations).toHaveLength(0);
  });
});

describe('Server-scope Rule 1 — literal/template (same as lib-core)', () => {
  it('fires on standalone string literal', () => {
    const code = `const name = 'AGENTS_MASTER_KEY';`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes("'AGENTS_MASTER_KEY' as a string literal"))).toBe(
      true,
    );
  });

  it("fires on bracket-access process.env['AGENTS_MASTER_KEY']", () => {
    // The bracket key is a Literal, so Rule 1 fires here in server scope too.
    const code = `const k = process.env['AGENTS_MASTER_KEY'];`;
    const violations = byokViolations(lintServerCode(code));
    expect(violations.some((m) => m.includes('AGENTS_MASTER_KEY'))).toBe(true);
  });
});
