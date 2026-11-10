#!/usr/bin/env node

import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const playgroundDir = resolve(scriptDir, '..');
const repoRoot = resolve(playgroundDir, '..', '..');
const linkedPackage = join(playgroundDir, 'node_modules', '@abaxxlabs', 'agents');
const requiredArtifacts = [
  join(repoRoot, 'dist', 'index.js'),
  join(repoRoot, 'dist', 'sql', 'index.js'),
  join(repoRoot, 'dist', 'bootstrap', 'index.js'),
];

let valid = true;

if (!existsSync(linkedPackage)) {
  console.error('[playground] Missing linked @abaxxlabs/agents dependency.');
  valid = false;
} else {
  const linkedRoot = realpathSync(linkedPackage);
  const canonicalRoot = realpathSync(repoRoot);
  if (linkedRoot !== canonicalRoot) {
    console.error('[playground] @abaxxlabs/agents does not resolve to the repository root.');
    console.error(`  expected: ${canonicalRoot}`);
    console.error(`  resolved: ${linkedRoot}`);
    valid = false;
  } else {
    const rootManifest = JSON.parse(readFileSync(join(canonicalRoot, 'package.json'), 'utf8'));
    const linkedManifest = JSON.parse(readFileSync(join(linkedRoot, 'package.json'), 'utf8'));
    if (linkedManifest.version !== rootManifest.version) {
      console.error('[playground] Linked package version does not match the repository package version.');
      valid = false;
    }
  }
}

const missingArtifacts = requiredArtifacts.filter((artifact) => !existsSync(artifact));
if (missingArtifacts.length > 0) {
  console.error('[playground] Missing built @abaxxlabs/agents entrypoints:');
  for (const artifact of missingArtifacts) console.error(`  ${artifact}`);
  valid = false;
}

if (!valid) {
  console.error([
    '',
    'Build the repository package, then install the playground link:',
    '',
    `  cd ${repoRoot}`,
    '  npm install',
    '  npm run build',
    '  cd demo/playground',
    '  npm install',
  ].join('\n'));
  process.exit(1);
}
