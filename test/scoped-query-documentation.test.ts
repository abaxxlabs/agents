import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const repositoryRoot = resolve(import.meta.dirname, '..');
const activeDocumentation = [
  'docs/internal/agents-e2e-harness-proposal.md',
  'demo/hackathon/SKILL-openclaw.md',
  'demo/hackathon/SCENARIOS.md',
  'demo/showcase/src/live/assertions.ts',
  'demo/user-stories/README.md',
  'demo/user-stories/story-02-column-scope/README.md',
  'packages/create-agents/template/src/scenario.ts',
  'src/cli/demo.ts',
  'src/mcp/tools.ts',
  'src/sql/types.ts',
];

const projectionDocumentation = [
  'docs/internal/agents-e2e-harness-proposal.md',
  'demo/hackathon/SKILL-openclaw.md',
  'demo/hackathon/SCENARIOS.md',
  'demo/showcase/src/live/assertions.ts',
  'demo/user-stories/story-02-column-scope/README.md',
  'packages/create-agents/template/src/scenario.ts',
];

describe('scoped-query documentation', () => {
  it('does not claim that an out-of-scope query returns ciphertext', () => {
    for (const relativePath of activeDocumentation) {
      const contents = readFileSync(resolve(repositoryRoot, relativePath), 'utf8');

      expect(contents, relativePath).not.toMatch(
        /out[- ]of[- ]scope[^\n]*(?:returns?|shows?|→|->)[^\n]*ciphertext/i,
      );
      expect(contents, relativePath).not.toMatch(/encryption[- ]only mode/i);
      expect(contents, relativePath).not.toContain('[ENCRYPTED]');
    }
  });

  it('states that projection violations are rejected before execution', () => {
    for (const relativePath of projectionDocumentation) {
      const contents = readFileSync(resolve(repositoryRoot, relativePath), 'utf8');

      expect(contents, relativePath).toMatch(
        /reject(?:ed|s)[\s\S]{0,120}?before\s+(?:SQL\s+)?execution/i,
      );
    }
  });

  it('preserves the lower-level ciphertext fallback contract', () => {
    const contents = readFileSync(resolve(repositoryRoot, 'src/encryption/column.ts'), 'utf8');

    expect(contents).toMatch(/preserve unscoped encrypted values as encoded data/);
  });
});
