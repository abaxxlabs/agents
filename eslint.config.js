/**
 * ESLint flat config — @abaxxlabs/agents
 *
 * Two BYOK trust-boundary rules enforce that the library core (`src/`) and the
 * server (`packages/server/src/`) cannot reach `AGENTS_MASTER_KEY` directly.
 * The master key must be sourced via `resolveMasterKeyFromEnv()` from
 * `@abaxxlabs/agents/bootstrap` (the sanctioned env-bridge) and threaded
 * through as a Buffer parameter.
 */

// @ts-check

import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

/** @type {import('eslint').Linter.Config[]} */
const config = [
  // ─── 1. Global ignores ────────────────────────────────────────────────────
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'dist-cjs/**',
      '.claude/**',
      'demo/**',
      'packages/*/node_modules/**',
      'packages/*/dist/**',
      // packages/create-agents stays excluded until its BYOK migration lands.
      'packages/create-agents/**',
    ],
  },

  // ─── 2. TypeScript base for src/ and test/ ────────────────────────────────
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // ─── 3. BYOK trust-boundary rules — src/ library core ─────────────────────
  //
  // Files exempt from these rules (the consumer boundary):
  //   - src/bootstrap/ — the sanctioned env-read site (resolveMasterKeyFromEnv).
  //   - src/cli/       — CLI tooling reads env at the entry point.
  {
    files: ['src/**/*.ts'],
    ignores: [
      'src/bootstrap/**/*.ts',
      'src/cli/**/*.ts',
    ],
    rules: {
      'no-restricted-syntax': [
        'error',

        // Catches the literal 'AGENTS_MASTER_KEY' (also covers bracket access
        // like process.env['AGENTS_MASTER_KEY'] — the bracket key is a Literal).
        {
          selector: "Literal[value='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a string literal inside library core (src/). " +
            'Use resolveMasterKeyFromEnv() from src/bootstrap/ instead.',
        },

        // Catches the template literal `AGENTS_MASTER_KEY`.
        {
          selector:
            "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a template literal inside library core (src/). " +
            'Use resolveMasterKeyFromEnv() from src/bootstrap/ instead.',
        },

        // Catches process.env.AGENTS_MASTER_KEY (dot notation).
        {
          selector:
            "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env'][property.name='AGENTS_MASTER_KEY']",
          message:
            '[BYOK] Do not read process.env.AGENTS_MASTER_KEY directly in library core (src/). ' +
            'Use resolveMasterKeyFromEnv() from src/bootstrap/ instead.',
        },

        // Catches `const { AGENTS_MASTER_KEY } = process.env`. The destructure
        // reaches into process.env via ObjectPattern, bypassing the rules above.
        {
          selector: "Property[key.name='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not destructure AGENTS_MASTER_KEY from process.env in library core (src/). " +
            'Use resolveMasterKeyFromEnv() from src/bootstrap/ instead.',
        },
      ],
    },
  },

  // ─── 4. TypeScript base for ──────────────────────────
  {
    files: ['packages/server/src/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // ─── 5. BYOK trust-boundary rules — ──────────────────
  //
  // The server legitimately reads many env vars (DATABASE_URL, OIDC_*, etc.).
  // Only AGENTS_MASTER_KEY is restricted: it must come from
  // resolveMasterKeyFromEnv() at bootstrap, threaded through as a Buffer.
  {
    files: ['packages/server/src/**/*.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',

        // Catches the literal 'AGENTS_MASTER_KEY' (also covers bracket access
        // like process.env['AGENTS_MASTER_KEY']).
        {
          selector: "Literal[value='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a string literal in. " +
            "Use resolveMasterKeyFromEnv() from '@abaxxlabs/agents/bootstrap' at bootstrap, " +
            "then thread the Buffer through AgentScope.create({ masterKey }).",
        },

        // Catches the template literal `AGENTS_MASTER_KEY`.
        {
          selector:
            "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a template literal in. " +
            'Use resolveMasterKeyFromEnv() from @abaxxlabs/agents/bootstrap instead.',
        },

        // Catches process.env.AGENTS_MASTER_KEY (dot notation).
        {
          selector:
            "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env'][property.name='AGENTS_MASTER_KEY']",
          message:
            '[BYOK] Do not read process.env.AGENTS_MASTER_KEY directly in. ' +
            'Use resolveMasterKeyFromEnv() at startup. Other env reads (DATABASE_URL, OIDC_*) remain unrestricted.',
        },

        // Catches `const { AGENTS_MASTER_KEY } = process.env`. The destructure
        // reaches into process.env via ObjectPattern, bypassing the rules above.
        {
          selector: "Property[key.name='AGENTS_MASTER_KEY']",
          message:
            "[BYOK] Do not destructure AGENTS_MASTER_KEY from process.env in. " +
            'Use resolveMasterKeyFromEnv() from @abaxxlabs/agents/bootstrap at startup.',
        },
      ],
    },
  },
];

export default config;
