/** ESLint flat config with TypeScript defaults and BYOK trust-boundary rules. */

import type { ESLint, Linter } from 'eslint';
import tsParser from '@typescript-eslint/parser';
import tsPlugin from '@typescript-eslint/eslint-plugin';

// The plugin's classic config type does not structurally match the flat-config type.
const tsPluginFlat = tsPlugin as unknown as ESLint.Plugin;
const tsRecommendedRules = tsPlugin.configs.recommended.rules;

export function byokRestrictions(boundary: string, remediation: string): Linter.RuleEntry {
  return [
    'error',
    {
      selector: "Literal[value='AGENTS_MASTER_KEY']",
      message: `[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a string literal in ${boundary}. ${remediation}`,
    },
    {
      selector: "TemplateLiteral[expressions.length=0][quasis.0.value.cooked='AGENTS_MASTER_KEY']",
      message: `[BYOK] Do not reference 'AGENTS_MASTER_KEY' as a template literal in ${boundary}. ${remediation}`,
    },
    {
      selector:
        "MemberExpression[object.type='MemberExpression'][object.object.name='process'][object.property.name='env'][property.name='AGENTS_MASTER_KEY']",
      message: `[BYOK] Do not read process.env.AGENTS_MASTER_KEY directly in ${boundary}. ${remediation}`,
    },
    {
      selector: "Property[key.name='AGENTS_MASTER_KEY']",
      message: `[BYOK] Do not destructure AGENTS_MASTER_KEY from process.env in ${boundary}. ${remediation}`,
    },
  ];
}

export function typescriptConfig(files: string[]): Linter.Config {
  return {
    files,
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022,
      },
    },
    plugins: {
      '@typescript-eslint': tsPluginFlat,
    },
    rules: {
      ...tsRecommendedRules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  };
}

const config: Linter.Config[] = [
  // ESLint already ignores all node_modules directories.
  {
    ignores: ['**/dist/**', '**/dist-cjs/**'],
  },

  // Shared TypeScript configuration.
  typescriptConfig(['src/**/*.ts', 'test/**/*.ts']),

  // Bootstrap and CLI code are the sanctioned environment boundaries.
  {
    files: ['src/**/*.ts'],
    ignores: ['src/bootstrap/**/*.ts', 'src/cli/**/*.ts'],
    rules: {
      'no-restricted-syntax': byokRestrictions(
        'library core (src/)',
        'Use resolveMasterKeyFromEnv() from src/bootstrap/ instead.',
      ),
    },
  },
];

export default config;
