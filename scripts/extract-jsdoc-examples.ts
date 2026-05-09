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
 * Extracts every @example block from src/**\/*.ts, synthesizes a scratch
 * TypeScript file, and runs tsc --noEmit to catch field/signature/export drift.
 * Use `ts failing` fence language to skip examples that intentionally show
 * invalid usage.
 *
 * Exit 0: all examples type-check. Exit 1: at least one substantive error.
 */

import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ExtractedExample {
  sourceFile: string;    // absolute path
  sourceLine: number;    // 1-based line of the @example tag
  fnName: string;        // synthesised function name (unique across all files)
  code: string;          // the example body (without leading/trailing blank lines)
  hasImports: boolean;   // true if the example uses import declarations
}

// ─── Config ───────────────────────────────────────────────────────────────────

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SCRATCH_FILE = path.join(REPO_ROOT, 'dist-jsdoc-examples.ts');

// Languages that indicate "skip this block — it intentionally fails to compile"
const FAILING_LANGS = new Set(['ts failing', 'typescript failing']);
// Languages that we extract (plus bare empty-string for no-lang fences)
const EXTRACT_LANGS = new Set(['ts', 'typescript', '']);

// TypeScript error codes that represent real API drift (not ambient-reference noise):
// TS2339: Property X does not exist on type Y
// TS2345: Argument of type X is not assignable to parameter of type Y
// TS2305: Module has no exported member X
// TS2307: Cannot find module X or its corresponding type declarations
// TS2353: Object literal may only specify known properties; X is not in type Y
// TS2554: Expected N arguments, but got M
// TS2740: Type is missing properties from type
// TS2741: Property X is missing in type Y but required in type Z
// TS2739: Type X is missing the following properties from type Y
const SIGNAL_CODES = new Set([2339, 2345, 2305, 2307, 2353, 2554, 2740, 2741, 2739]);

// Error codes we always suppress (noise from partial-snippet context):
// TS2304: Cannot find name X  (expected for ambient snippet vars like `agentVerifier`)
// TS18004: No value exists in scope for shorthand property X
// TS7006: Parameter X implicitly has an 'any' type  (inline arrow fn params in snippets)
// TS7022: X implicitly has type 'any' (forward-reference in snippet)
// TS2448: Block-scoped variable used before its declaration (snippet self-ref)
// TS2393: Duplicate function implementation (caught by name deduplication now)
// TS2695: Left side of comma operator is unused (from our void() footer line)
// TS1232: An import declaration can only be used at the top level (import inside fn)
// TS2451: Cannot redeclare block-scoped variable (multiple const backend in snippets)
const SUPPRESS_CODES = new Set([2304, 18004, 7006, 7022, 2448, 2393, 2695, 1232, 2451, 2552]);

// ─── File discovery ───────────────────────────────────────────────────────────

function findTsFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findTsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      results.push(full);
    }
  }
  return results;
}

// ─── Extract JSDoc @example blocks from a single source file ──────────────────

function extractExamplesFromFile(
  filePath: string,
  globalCounter: { n: number },
): ExtractedExample[] {
  const sourceText = fs.readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.ES2022,
    /* setParentNodes */ true,
  );

  const examples: ExtractedExample[] = [];
  const baseName = path.basename(filePath, '.ts').replace(/[^a-zA-Z0-9]/g, '_');

  // Walk the AST and collect JSDoc nodes
  function visit(node: ts.Node): void {
    // getJSDocCommentsAndTags walks up to find JSDoc attached to this node.
    // Use ts.getJSDocTags for the tag-only view.
    const tags = ts.getJSDocTags(node);
    for (const tag of tags) {
      if (tag.tagName.text !== 'example') continue;

      // Line of the @example tag (1-based)
      const tagLine = sourceFile.getLineAndCharacterOfPosition(tag.getStart()).line + 1;

      // The comment text after @example
      const rawComment = typeof tag.comment === 'string'
        ? tag.comment
        : Array.isArray(tag.comment)
          ? (tag.comment as Array<{ text?: string }>)
              .map(c => (typeof c.text === 'string' ? c.text : ''))
              .join('')
          : '';

      const counter = globalCounter.n++;
      const fnName = `__jsdoc_example_${baseName}_${counter}`;
      const extracted = parseExampleComment(rawComment, filePath, tagLine, fnName);
      if (extracted !== null) {
        examples.push(extracted);
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return examples;
}

// ─── Parse the text content of a single @example annotation ──────────────────

function parseExampleComment(
  raw: string,
  filePath: string,
  tagLine: number,
  fnName: string,
): ExtractedExample | null {
  const trimmed = raw.trim();

  // ── Fenced code block: ```lang ... ``` ──────────────────────────────────────
  const fenceRe = /^```([a-z ]*)\n([\s\S]*?)```/m;
  const fenceMatch = trimmed.match(fenceRe);
  if (fenceMatch) {
    const lang = fenceMatch[1].trim().toLowerCase();
    if (FAILING_LANGS.has(lang)) {
      const rel = path.relative(REPO_ROOT, filePath);
      console.log(`  [skip-failing] ${rel}:${tagLine} — intentional-fail fence`);
      return null;
    }
    if (!EXTRACT_LANGS.has(lang)) {
      // Non-TypeScript fence (e.g., ```shell, ```json) — skip silently
      return null;
    }
    const code = fenceMatch[2].trimEnd();
    const hasImports = /^\s*import\s/m.test(code);
    return { sourceFile: filePath, sourceLine: tagLine, fnName, code, hasImports };
  }

  // ── Bare indented code (no fences) ──────────────────────────────────────────
  if (trimmed.length === 0) return null;

  // Heuristic: must contain at least one TS pattern to extract
  const looksLikeCode = /\b(const|let|var|await|new|=>|import )\b/.test(trimmed);
  if (!looksLikeCode) return null;

  const hasImports = /^\s*import\s/m.test(trimmed);
  return { sourceFile: filePath, sourceLine: tagLine, fnName, code: trimmed, hasImports };
}

// ─── Synthesise the scratch file ──────────────────────────────────────────────

function buildScratchFile(examples: ExtractedExample[]): string {
  const lines: string[] = [];

  lines.push('// AUTO-GENERATED by scripts/extract-jsdoc-examples.ts — DO NOT EDIT');
  lines.push('// git-ignored. Retained on failure; deleted on success.');
  lines.push('// Each example is in its own async function to prevent const collisions.');
  lines.push('');

  // ── Top-level imports from the package source ────────────────────────────────
  // We import from src/ directly so tsc sees live types, not dist/.
  // Symbols that examples reference but don't import explicitly are brought in here.
  lines.push(`import * as _api from './src/index.js';`);
  lines.push(`import * as _sqlApi from './src/sql/index.js';`);
  lines.push(`import type { StorageBackend, RevocationStore } from './src/storage/index.js';`);
  lines.push(`import type { IdentityContext } from './src/storage/identity-context.js';`);
  lines.push(`import type { AgentVerifyResult } from './src/identity/agent-verifier.js';`);
  lines.push('');

  // ── Ambient declarations for commonly-used partial-snippet identifiers ────────
  // These pre-declare variables that appear in partial snippets where the full
  // setup context is not shown. They prevent TS2304 ("cannot find name X") noise
  // from drowning out real API-surface errors.
  lines.push('// Ambient stubs for partial snippet context variables');
  lines.push(`declare const agentVerifier: { verify(opts: { bindingJwt: string; agentDid: string }): Promise<AgentVerifyResult> };`);
  lines.push(`declare const backend: StorageBackend;`);
  lines.push(`declare const connectionString: string;`);
  lines.push(`declare const keystore: unknown;`);
  lines.push(`declare const identity: { did: string };`);
  lines.push(`declare const sessionManager: { getActiveTokens(): string[] };`);
  lines.push(`declare const bindingJwt: string;`);
  lines.push(`declare const agentDid: string;`);
  lines.push(`declare const bearer: string;`);
  lines.push(`declare const vcVerifier: unknown;`);
  lines.push(`declare const trustAnchorStore: unknown;`);
  lines.push('');

  // ── Named API re-exports so examples can use short names ────────────────────
  lines.push(`const { AgentScope } = _sqlApi;`);
  lines.push('');

  // ── One async function wrapper per example ───────────────────────────────────
  for (const ex of examples) {
    const relPath = path.relative(REPO_ROOT, ex.sourceFile);
    lines.push(`// ─── ${relPath}:${ex.sourceLine} ───`);
    lines.push(`async function ${ex.fnName}() {`);

    if (ex.hasImports) {
      // Examples containing import declarations cannot be placed inside a function.
      // Emit the imports as dynamic-import equivalents or just suppress the example
      // with a comment. For v1 we skip the import lines and keep the rest.
      // This means imports-inside-function noise is suppressed at source rather
      // than relying on SUPPRESS_CODES. We still check method calls / type usage.
      for (const codeLine of ex.code.split('\n')) {
        const stripped = codeLine.trimStart();
        if (stripped.startsWith('import ')) {
          lines.push(`  // [import suppressed — cannot appear inside function body]`);
          lines.push(`  // ${codeLine}`);
        } else {
          lines.push(`  ${codeLine}`);
        }
      }
    } else {
      for (const codeLine of ex.code.split('\n')) {
        lines.push(`  ${codeLine}`);
      }
    }

    lines.push(`}`);
    lines.push('');
  }

  // ── Footer: suppress "declared but never read" on wrapper functions ──────────
  if (examples.length > 0) {
    // Each function reference on its own line to keep error mapping simple
    lines.push(`// Suppress unused-function warnings`);
    for (const ex of examples) {
      lines.push(`void ${ex.fnName};`);
    }
  }
  lines.push('');
  lines.push(`void (_api);`);
  lines.push(`void (_sqlApi);`);

  return lines.join('\n');
}

// ─── Run tsc on the scratch file and filter errors ────────────────────────────

interface TscResult {
  ok: boolean;
  signalErrors: string[];   // errors matching SIGNAL_CODES (real drift)
  suppressedCount: number;  // noise errors that were filtered
  rawOutput: string;
}

function runTsc(scratchFile: string): TscResult {
  // Write a minimal tsconfig that targets the scratch file + src.
  const scratchTsConfig = {
    extends: './tsconfig.json',
    compilerOptions: {
      // The scratch file is at repo root so rootDir must cover both '.' and 'src/'
      rootDir: '.',
      noEmit: true,
      // Relax some strict checks that are too noisy for snippet-style code
      noUnusedLocals: false,
      noUnusedParameters: false,
    },
    include: [path.basename(scratchFile), 'src/**/*.ts'],
    exclude: ['node_modules', 'dist', 'test', 'scripts'],
  };

  const tsconfigPath = path.join(REPO_ROOT, 'tsconfig.jsdoc-check.json');
  fs.writeFileSync(tsconfigPath, JSON.stringify(scratchTsConfig, null, 2));

  let rawOutput = '';
  try {
    rawOutput = execSync(
      `npx tsc --project ${path.basename(tsconfigPath)} 2>&1`,
      { cwd: REPO_ROOT, encoding: 'utf-8' },
    );
  } catch (err: unknown) {
    rawOutput = err instanceof Error && 'stdout' in err
      ? String((err as NodeJS.ErrnoException & { stdout?: string }).stdout ?? '')
      : String(err);
  } finally {
    try { fs.unlinkSync(tsconfigPath); } catch {}
  }

  // Parse tsc output and classify each error line
  const signalErrors: string[] = [];
  let suppressedCount = 0;
  let currentError: string[] = [];
  let currentCodeIsSignal: boolean | null = null;

  function flushCurrent() {
    if (currentError.length === 0) return;
    if (currentCodeIsSignal === true) {
      signalErrors.push(currentError.join('\n'));
    } else {
      suppressedCount++;
    }
    currentError = [];
    currentCodeIsSignal = null;
  }

  for (const line of rawOutput.split('\n')) {
    // Primary error line: "file.ts(line,col): error TSxxxx: message"
    const primaryMatch = line.match(/: error TS(\d+):/);
    if (primaryMatch) {
      flushCurrent();
      const code = parseInt(primaryMatch[1], 10);
      currentCodeIsSignal = SIGNAL_CODES.has(code) && !SUPPRESS_CODES.has(code);
      currentError.push(line);
    } else if (currentError.length > 0 && (line.startsWith(' ') || line.trim() === '')) {
      // Continuation line or blank within an error block
      currentError.push(line);
    } else if (line.trim().length > 0) {
      // Non-error line (e.g., tsc summary)
      flushCurrent();
    }
  }
  flushCurrent();

  return {
    ok: signalErrors.length === 0,
    signalErrors,
    suppressedCount,
    rawOutput,
  };
}

// ─── Map scratch-file line numbers back to originating source file:line ────────

// We rebuild the scratch file line map by parsing the generated content directly.
function buildLineMap(
  scratchContent: string,
  examples: ExtractedExample[],
): Map<number, ExtractedExample> {
  const lines = scratchContent.split('\n');
  const map = new Map<number, ExtractedExample>();

  // Find each "// ─── relPath:line ───" header and map subsequent lines
  // to their example. The function body starts 2 lines after the header.
  for (let i = 0; i < lines.length; i++) {
    const headerMatch = lines[i].match(/^\/\/ ─── (.+):(\d+) ───/);
    if (!headerMatch) continue;

    const relPath = headerMatch[1];
    const tagLine = parseInt(headerMatch[2], 10);
    const ex = examples.find(
      e => path.relative(REPO_ROOT, e.sourceFile) === relPath && e.sourceLine === tagLine,
    );
    if (!ex) continue;

    // Line i+1 is `async function ...() {`; code starts at i+2
    const codeLines = ex.code.split('\n').length;
    for (let j = i + 2; j < i + 2 + codeLines + 5 && j < lines.length; j++) {
      map.set(j + 1, ex); // +1 because line numbers are 1-based
    }
  }
  return map;
}

function annotateSignalErrors(
  signalErrors: string[],
  lineMap: Map<number, ExtractedExample>,
): string[] {
  const scratchBasename = path.basename(SCRATCH_FILE).replace('.', '\\.');
  const re = new RegExp(`^${scratchBasename}\\((\\d+),\\d+\\):`);

  return signalErrors.map(block => {
    const firstLine = block.split('\n')[0];
    const m = firstLine.match(re);
    if (m) {
      const lineNum = parseInt(m[1], 10);
      const ex = lineMap.get(lineNum);
      if (ex) {
        const rel = path.relative(REPO_ROOT, ex.sourceFile);
        return `[JSDoc @example at ${rel}:${ex.sourceLine}]\n${block}`;
      }
    }
    return block;
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('extract-jsdoc-examples: scanning src/ for @example blocks...');

  const srcFiles = findTsFiles(path.join(REPO_ROOT, 'src'));
  srcFiles.sort();

  const globalCounter = { n: 0 };
  const allExamples: ExtractedExample[] = [];

  for (const f of srcFiles) {
    const exs = extractExamplesFromFile(f, globalCounter);
    if (exs.length > 0) {
      const rel = path.relative(REPO_ROOT, f);
      console.log(`  ${rel}: ${exs.length} example(s)`);
      allExamples.push(...exs);
    }
  }

  console.log(`\nextract-jsdoc-examples: ${allExamples.length} total example(s) across ${srcFiles.length} scanned files`);

  if (allExamples.length === 0) {
    console.log('  No examples found — nothing to type-check. Exiting 0.');
    process.exit(0);
  }

  // Build and write scratch file
  const scratchContent = buildScratchFile(allExamples);
  fs.writeFileSync(SCRATCH_FILE, scratchContent, 'utf-8');
  console.log(`extract-jsdoc-examples: wrote scratch file (${scratchContent.split('\n').length} lines)`);

  // Build line map for error annotation
  const lineMap = buildLineMap(scratchContent, allExamples);

  // Run tsc and filter errors
  console.log('extract-jsdoc-examples: running tsc --noEmit...\n');
  const result = runTsc(SCRATCH_FILE);

  console.log(`  Signal errors (real drift): ${result.signalErrors.length}`);
  console.log(`  Suppressed noise errors:    ${result.suppressedCount}`);

  if (result.ok) {
    console.log('\nextract-jsdoc-examples: ALL EXAMPLES TYPE-CHECK CLEAN');
    try { fs.unlinkSync(SCRATCH_FILE); } catch {}
    process.exit(0);
  } else {
    const annotated = annotateSignalErrors(result.signalErrors, lineMap);
    console.error('\nextract-jsdoc-examples: TYPE ERRORS IN JSDoc @example BLOCKS\n');
    console.error('=' .repeat(72));
    for (const err of annotated) {
      console.error(err);
      console.error('-'.repeat(72));
    }
    console.error(`\nFound ${result.signalErrors.length} drift error(s) in JSDoc examples.`);
    console.error(`Scratch file retained for inspection: ${SCRATCH_FILE}`);
    console.error('Fix the JSDoc or the types they reference, then re-run.');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('extract-jsdoc-examples: unexpected error:', err);
  process.exit(2);
});
