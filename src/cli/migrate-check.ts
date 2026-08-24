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
 * CLI: agents migrate-check
 *
 * Read-only diagnostic that scans a consumer codebase for BYOK migration signals
 * and categorizes the codebase into one of the four migration cases documented in
 * `docs/migrations/byok.md`. Writes nothing; no network connections.
 *
 * Regex, not AST: an AST parse would be more precise but adds heavyweight deps and
 * parse-failure modes (mixed JS/TS, syntax errors, decorator metadata). The failure
 * mode for regex over-reporting is "user manually inspects the line" — acceptable for
 * a one-shot read-only categorizer.
 *
 * Excluded: node_modules/, dist/, build/, .git/, coverage/, .next/, .nuxt/, dotfiles,
 * non-source files (.md, .json, .yaml), and files larger than 1 MB.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface MigrateCheckOptions {
  /** Root directory to scan. Defaults to `process.cwd()`. */
  cwd?: string;
  /** Emit machine-readable JSON instead of human-readable report. */
  json?: boolean;
}

/** A single scan finding — one signal at one source location. */
export interface Hit {
  file: string;
  line: number;
  /**
   * Type of signal detected. Keep in sync with `categorize()`.
   *
   * Advisory variants (`env-dev-mode`, `env-keystore-path`, `env-trusted-servers`,
   * `env-consumer-domains`) surface env-var reads that the library no longer performs
   * directly. They do NOT affect BYOK case categorization — they are reported in a
   * separate advisory section.
   */
  type:
    | 'env-read'
    | 'env-write'
    | 'config-master-key'
    | 'agentscope-create'
    | 'env-dev-mode'
    | 'env-keystore-path'
    | 'env-trusted-servers'
    | 'env-consumer-domains';
  /** The source line, trimmed and length-capped. Truncated if very long. */
  snippet: string;
}

/** Top-level categorization result. */
export interface Categorization {
  /** Migration case from `docs/migrations/byok.md`, or null if no signals found. */
  caseId:
    | '#1'
    | '#2'
    | '#3-#4'
    | 'trap'
    | 'no-master-key'
    | 'no-agents-code'
    | 'config-advisory-only';
  /** Human-readable summary headline. */
  headline: string;
  /** Pointer paragraphs — what to read in `docs/migrations/byok.md`. */
  guidance: string[];
}

const SCAN_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);

const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.cache',
  'tmp',
]);

const FILE_SIZE_LIMIT_BYTES = 1_000_000;
const SNIPPET_MAX_LENGTH = 160;
/**
 * Recursion depth ceiling for the directory walk. Cap chosen to be deeper
 * than any realistic monorepo (Nx workspaces top out around 10 levels) but
 * shallow enough to bail before stack-overflow on pathological cycles
 * (Docker volume mounts, bind-mounted self-references, broken symlinks
 * that fs.readdirSync would still resolve via {withFileTypes: true}'s
 * isDirectory check).
 */
const MAX_WALK_DEPTH = 20;

// ─── Pattern matchers ─────────────────────────────────────────────────────────
//
// Each matcher returns the Hit type if matched, or null. Order matters: the
// scanner checks env-write FIRST so we don't double-report a write line as
// also being a read (the RHS of an assignment may match the read pattern).

/**
 * env WRITE — `process.env.AGENTS_MASTER_KEY = ...`. Distinct from read
 * because writes are the demo/showcase control-channel pattern that the
 * migration explicitly removes.
 */
const ENV_WRITE_RE =
  /\bprocess\.env(?:\.AGENTS_MASTER_KEY|\[\s*['"]AGENTS_MASTER_KEY['"]\s*\])\s*=/;

/**
 * env READ — any access pattern that reads the env var.
 *   - dot:       `process.env.AGENTS_MASTER_KEY`
 *   - bracket:   `process.env['AGENTS_MASTER_KEY']` (single or double quote)
 *   - destructure: `const { AGENTS_MASTER_KEY } = process.env`
 *
 * The destructure pattern is matched separately because the destructure
 * occurs syntactically before `process.env` on the line (LHS comes first).
 */
const ENV_READ_DOT_RE = /\bprocess\.env\.AGENTS_MASTER_KEY\b/;
const ENV_READ_BRACKET_RE = /\bprocess\.env\[\s*['"]AGENTS_MASTER_KEY['"]\s*\]/;
const ENV_READ_DESTRUCTURE_RE = /\{\s*[^}]*\bAGENTS_MASTER_KEY\b[^}]*\}\s*=\s*process\.env\b/;

/**
 * Config field — literal `encryption.masterKey` substring. Catches both the
 * dot-access reference (rare) AND the property-set inside an `AgentScopeConfig`
 * object literal when the developer typed the dotted path in a comment or
 * JSDoc. Combined with the inline match below for the actual config-object
 * pattern.
 */
const CONFIG_DOT_RE = /\bencryption\.masterKey\b/;

/**
 * Config field — inline pattern `encryption: { ... masterKey: ... }`. We match
 * `masterKey\s*:` on a line that ALSO contains `encryption` within a small
 * window (same line). Multi-line inline objects are caught by the dot pattern
 * above when the developer references them in surrounding code or docs;
 * truly bespoke deep-nested patterns are the rare case worth the manual
 * inspection step.
 */
const CONFIG_INLINE_RE = /\bencryption\s*:.*\bmasterKey\s*:/;

/**
 * AgentScope.create call site — both `AgentScope.create(` and the rare
 * imported alias `create(`. We use the explicit class form because
 * library-shape consumers always go through `AgentScope.create`; aliasing
 * is rare enough to skip and the false-positive cost is high.
 */
const AGENTSCOPE_CREATE_RE = /\bAgentScope\.create\s*\(/;

/**
 * `process.env.AGENTS_DEV_MODE` reads. Same three access shapes as the master-key
 * reader (dot, bracket, destructure). Detected separately so the report can advise
 * on the config-field promotion without affecting BYOK case categorization.
 */
const ENV_DEV_MODE_DOT_RE = /\bprocess\.env\.AGENTS_DEV_MODE\b/;
const ENV_DEV_MODE_BRACKET_RE = /\bprocess\.env\[\s*['"]AGENTS_DEV_MODE['"]\s*\]/;
const ENV_DEV_MODE_DESTRUCTURE_RE = /\{\s*[^}]*\bAGENTS_DEV_MODE\b[^}]*\}\s*=\s*process\.env\b/;

/**
 * `process.env.AGENTS_KEYSTORE_PATH` reads. Same three access shapes. Detected
 * separately to advise on `AgentScopeConfig.keystore.path` promotion without
 * affecting BYOK case categorization.
 */
const ENV_KEYSTORE_PATH_DOT_RE = /\bprocess\.env\.AGENTS_KEYSTORE_PATH\b/;
const ENV_KEYSTORE_PATH_BRACKET_RE = /\bprocess\.env\[\s*['"]AGENTS_KEYSTORE_PATH['"]\s*\]/;
const ENV_KEYSTORE_PATH_DESTRUCTURE_RE =
  /\{\s*[^}]*\bAGENTS_KEYSTORE_PATH\b[^}]*\}\s*=\s*process\.env\b/;

/**
 * `process.env.AGENTS_TRUSTED_SERVERS` reads. Same three access shapes. The env-read
 * moved from `LocalTrustAnchorStore` to the consumer-boundary helper
 * `resolveTrustedServersFromEnv()` in `@abaxxlabs/agents/bootstrap`.
 */
const ENV_TRUSTED_SERVERS_DOT_RE = /\bprocess\.env\.AGENTS_TRUSTED_SERVERS\b/;
const ENV_TRUSTED_SERVERS_BRACKET_RE = /\bprocess\.env\[\s*['"]AGENTS_TRUSTED_SERVERS['"]\s*\]/;
const ENV_TRUSTED_SERVERS_DESTRUCTURE_RE =
  /\{\s*[^}]*\bAGENTS_TRUSTED_SERVERS\b[^}]*\}\s*=\s*process\.env\b/;

/**
 * `process.env.AGENTS_CONSUMER_DOMAINS` reads. Same three access shapes. The env-read
 * was removed from the library; promoted to `AgentScopeConfig.orgBoundary.extraConsumerDomains`
 * so both auth engines receive the same value from a single caller-passed source.
 */
const ENV_CONSUMER_DOMAINS_DOT_RE = /\bprocess\.env\.AGENTS_CONSUMER_DOMAINS\b/;
const ENV_CONSUMER_DOMAINS_BRACKET_RE = /\bprocess\.env\[\s*['"]AGENTS_CONSUMER_DOMAINS['"]\s*\]/;
const ENV_CONSUMER_DOMAINS_DESTRUCTURE_RE =
  /\{\s*[^}]*\bAGENTS_CONSUMER_DOMAINS\b[^}]*\}\s*=\s*process\.env\b/;

// ─── Scanner ──────────────────────────────────────────────────────────────────

/**
 * Walk `root` recursively and apply `visit` to each scannable file.
 * Skips directories in SKIP_DIRS and any name starting with `.`. Bails
 * silently after MAX_WALK_DEPTH levels to defend against pathological
 * cycle structures.
 */
function walk(root: string, visit: (filePath: string) => void, depth = 0): void {
  if (depth > MAX_WALK_DEPTH) return;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    // Permission denied / not a directory — skip silently. The caller already
    // chose to scan this path; we don't need to surface every EACCES.
    return;
  }

  for (const entry of entries) {
    const full = path.join(root, entry.name);

    if (entry.isDirectory()) {
      // Skip dot-directories (.git, .vscode, etc.) and the explicit skip list.
      if (entry.name.startsWith('.')) continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, visit, depth + 1);
      continue;
    }

    if (entry.isFile()) {
      if (!SCAN_EXTENSIONS.has(path.extname(entry.name))) continue;
      visit(full);
    }
    // Symlinks are not followed — typical TS/JS projects don't symlink source
    // and following them risks loops in monorepos.
  }
}

/**
 * Scan one file line-by-line and append Hits for each pattern match.
 * Files larger than FILE_SIZE_LIMIT_BYTES are skipped to avoid blowing
 * memory on minified bundles or generated artifacts that slipped past the
 * directory filter.
 */
function scanFile(filePath: string, root: string, hits: Hit[]): void {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return;
  }
  if (stat.size > FILE_SIZE_LIMIT_BYTES) return;

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }

  const relative = path.relative(root, filePath);
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? '';
    const lineNo = i + 1;
    const snippet = clampSnippet(rawLine);

    // Order matters: write before read (an assignment line matches both).
    if (ENV_WRITE_RE.test(rawLine)) {
      hits.push({ file: relative, line: lineNo, type: 'env-write', snippet });
      continue;
    }

    if (
      ENV_READ_DOT_RE.test(rawLine) ||
      ENV_READ_BRACKET_RE.test(rawLine) ||
      ENV_READ_DESTRUCTURE_RE.test(rawLine)
    ) {
      hits.push({ file: relative, line: lineNo, type: 'env-read', snippet });
      // Don't `continue` — a single line might also reference encryption.masterKey
      // (e.g. a JSDoc example). Fall through so we record both.
    }

    if (CONFIG_DOT_RE.test(rawLine) || CONFIG_INLINE_RE.test(rawLine)) {
      hits.push({ file: relative, line: lineNo, type: 'config-master-key', snippet });
    }

    if (AGENTSCOPE_CREATE_RE.test(rawLine)) {
      hits.push({ file: relative, line: lineNo, type: 'agentscope-create', snippet });
    }

    // Advisory dev-mode env-read scan. Independent of the four BYOK cases;
    // reported in its own section of the output.
    if (
      ENV_DEV_MODE_DOT_RE.test(rawLine) ||
      ENV_DEV_MODE_BRACKET_RE.test(rawLine) ||
      ENV_DEV_MODE_DESTRUCTURE_RE.test(rawLine)
    ) {
      hits.push({ file: relative, line: lineNo, type: 'env-dev-mode', snippet });
    }

    // Advisory keystore-path env-read scan.
    if (
      ENV_KEYSTORE_PATH_DOT_RE.test(rawLine) ||
      ENV_KEYSTORE_PATH_BRACKET_RE.test(rawLine) ||
      ENV_KEYSTORE_PATH_DESTRUCTURE_RE.test(rawLine)
    ) {
      hits.push({ file: relative, line: lineNo, type: 'env-keystore-path', snippet });
    }

    // Advisory trusted-servers env-read scan.
    if (
      ENV_TRUSTED_SERVERS_DOT_RE.test(rawLine) ||
      ENV_TRUSTED_SERVERS_BRACKET_RE.test(rawLine) ||
      ENV_TRUSTED_SERVERS_DESTRUCTURE_RE.test(rawLine)
    ) {
      hits.push({ file: relative, line: lineNo, type: 'env-trusted-servers', snippet });
    }

    // Advisory consumer-domains env-read scan.
    if (
      ENV_CONSUMER_DOMAINS_DOT_RE.test(rawLine) ||
      ENV_CONSUMER_DOMAINS_BRACKET_RE.test(rawLine) ||
      ENV_CONSUMER_DOMAINS_DESTRUCTURE_RE.test(rawLine)
    ) {
      hits.push({ file: relative, line: lineNo, type: 'env-consumer-domains', snippet });
    }
  }
}

function clampSnippet(line: string): string {
  const trimmed = line.trim();
  if (trimmed.length <= SNIPPET_MAX_LENGTH) return trimmed;
  return trimmed.slice(0, SNIPPET_MAX_LENGTH - 3) + '...';
}

// ─── Categorization ───────────────────────────────────────────────────────────

/**
 * Categorize the scan output into one of the four migration cases (or the
 * trap / no-signals states). Pure function over Hit counts — no side effects.
 */
export function categorize(hits: Hit[]): Categorization {
  const envReads = hits.filter((h) => h.type === 'env-read').length;
  const envWrites = hits.filter((h) => h.type === 'env-write').length;
  const configHits = hits.filter((h) => h.type === 'config-master-key').length;
  const createHits = hits.filter((h) => h.type === 'agentscope-create').length;
  // Advisory hits count toward "is this codebase using agents?" but do NOT influence
  // BYOK case categorization. Without this branch, advisory-only codebases would get
  // the "no-agents-code" headline while advisory blocks were still emitted — contradictory.
  const sessionSevenHits = hits.filter(
    (h) =>
      h.type === 'env-dev-mode' ||
      h.type === 'env-keystore-path' ||
      h.type === 'env-trusted-servers' ||
      h.type === 'env-consumer-domains',
  ).length;

  if (
    envReads === 0 &&
    envWrites === 0 &&
    configHits === 0 &&
    createHits === 0 &&
    sessionSevenHits === 0
  ) {
    return {
      caseId: 'no-agents-code',
      headline: 'No @abaxxlabs/agents signals found in this directory.',
      guidance: [
        'Run from the root of a consumer project that imports @abaxxlabs/agents.',
        'If you ARE in such a directory and got this report, the scan may have',
        'missed your code paths — please file an issue with the directory layout.',
      ],
    };
  }

  // Advisory-only: no BYOK signals but env-var reads that the library no longer performs.
  if (
    sessionSevenHits > 0 &&
    envReads === 0 &&
    envWrites === 0 &&
    configHits === 0 &&
    createHits === 0
  ) {
    return {
      caseId: 'config-advisory-only',
      headline: 'Library-shrink env reads detected (v0.10.0); no BYOK migration signals.',
      guidance: [
        'Each advisory section below names the specific env var and the v0.10.0',
        'migration path. Apply each migration at your consumer boundary; the',
        'library no longer reads any of these env vars directly.',
        'Core library code intentionally reads NODE_ENV and CI; MCP entrypoints have separate configuration.',
      ],
    };
  }

  // AgentScope.create found but no master-key source — may be KMS or a custom path.
  if (createHits > 0 && envReads === 0 && configHits === 0) {
    return {
      caseId: 'no-master-key',
      headline: 'AgentScope.create call sites found but no detected master-key source.',
      guidance: [
        'You may be sourcing the master key from KMS, a config callback, or',
        'another path the scanner did not recognize. Inspect each AgentScope.create',
        'call manually and confirm the second `injections` argument supplies a',
        '32-byte Buffer via injections.masterKey.',
        'For non-env hex sources see docs/migrations/byok.md § "Case #4".',
      ],
    };
  }

  // Trap: both env-read and config-field master-key sites present — env was silently
  // winning. The environment audit must run before any migration.
  if (envReads > 0 && configHits > 0) {
    return {
      caseId: 'trap',
      headline: 'Trap detected — both env-read AND encryption.masterKey config sites present.',
      guidance: [
        'Previously the env var silently won and the config field was dead code.',
        'Run the environment audit in docs/migrations/byok.md § "Environment audit',
        '(do this first)" before applying any of the four worked examples.',
        'Once you have identified the canonical key value, you will be in case #1',
        '(env-only) or case #2 (config-hex). Do NOT migrate without the audit —',
        'copying the wrong key into injections.masterKey will corrupt every',
        'encrypted column on first boot.',
      ],
    };
  }

  if (envReads > 0 && configHits === 0) {
    const envWriteWarning =
      envWrites > 0
        ? [
            `Also detected ${envWrites} process.env.AGENTS_MASTER_KEY = ... write site(s) —`,
            'this is the demo/showcase control-channel pattern. Replace each write',
            'with an explicit Buffer argument to AgentScope.create per § "Case #1".',
          ]
        : [];
    return {
      caseId: '#1',
      headline: 'Case #1 — env-only master key.',
      guidance: [
        'If you are keeping the same key value: see docs/migrations/byok.md § "Case #1".',
        'If you are rotating the key as part of this upgrade (KMS migration, fresh',
        'credential, security incident): see § "Case #3" or § "Case #4" and read',
        'the rewrapColumnKey migration protocol BEFORE applying the upgrade.',
        ...envWriteWarning,
      ],
    };
  }

  if (configHits > 0 && envReads === 0) {
    return {
      caseId: '#2',
      headline: 'Case #2 — config-hex master key (no env-read sites detected).',
      guidance: [
        'See docs/migrations/byok.md § "Case #2".',
        'The hex string moves out of config (no longer a config field at the',
        'type level) and becomes a Buffer in injections. Decoding moves to your',
        'consumer boundary via parseMasterKeyHex from @abaxxlabs/agents/bootstrap.',
        'If you are also rotating the key value: see § "Case #4".',
      ],
    };
  }

  // Env-writes only, no reads, no config — unusual; categorize as #1-adjacent.
  return {
    caseId: '#1',
    headline: 'Master-key signal found (env writes only — unusual pattern).',
    guidance: [
      'Detected env writes but no reads or config-writes. This is rare; you may',
      'be in a test fixture or migration script. See docs/migrations/byok.md § "Case #1"',
      'and replace the writes with explicit Buffer arguments to AgentScope.create.',
    ],
  };
}

// ─── Output ───────────────────────────────────────────────────────────────────

function printReport(hits: Hit[], report: Categorization, root: string): void {
  const envReads = hits.filter((h) => h.type === 'env-read').length;
  const envWrites = hits.filter((h) => h.type === 'env-write').length;
  const configHits = hits.filter((h) => h.type === 'config-master-key').length;
  const createHits = hits.filter((h) => h.type === 'agentscope-create').length;
  const devModeHits = hits.filter((h) => h.type === 'env-dev-mode').length;
  const keystorePathHits = hits.filter((h) => h.type === 'env-keystore-path').length;
  const trustedServersHits = hits.filter((h) => h.type === 'env-trusted-servers').length;
  const consumerDomainsHits = hits.filter((h) => h.type === 'env-consumer-domains').length;

  console.log(`[agents migrate-check] Scanning ${root}\n`);

  console.log('Found:');
  console.log(`  ${envReads} process.env.AGENTS_MASTER_KEY read site(s)`);
  console.log(`  ${envWrites} process.env.AGENTS_MASTER_KEY write site(s)`);
  console.log(`  ${configHits} encryption.masterKey reference(s)`);
  console.log(`  ${createHits} AgentScope.create(...) call site(s)`);
  console.log(`  ${devModeHits} process.env.AGENTS_DEV_MODE read site(s)`);
  console.log(`  ${keystorePathHits} process.env.AGENTS_KEYSTORE_PATH read site(s)`);
  console.log(`  ${trustedServersHits} process.env.AGENTS_TRUSTED_SERVERS read site(s)`);
  console.log(`  ${consumerDomainsHits} process.env.AGENTS_CONSUMER_DOMAINS read site(s)`);
  console.log();

  console.log(`Result: ${report.headline}`);
  console.log();

  for (const line of report.guidance) {
    console.log(`  ${line}`);
  }
  console.log();

  if (devModeHits > 0) {
    console.log('Advisory — AGENTS_DEV_MODE migration:');
    console.log('  v0.10.0 promotes this env var to `AgentScopeConfig.devMode`. The library');
    console.log('  no longer reads `process.env.AGENTS_DEV_MODE` directly. Bridge from env at');
    console.log('  your consumer boundary:');
    console.log('    devMode: process.env.AGENTS_DEV_MODE === "true"');
    console.log('  Then pass into `AgentScope.create({ ..., devMode })`.');
    console.log('  NODE_ENV gates remain in place as defense-in-depth — do NOT replace them.');
    console.log();
  }

  if (keystorePathHits > 0) {
    console.log('Advisory — AGENTS_KEYSTORE_PATH migration:');
    console.log('  v0.10.0 promotes this env var to `AgentScopeConfig.keystore.path`. The');
    console.log('  library no longer reads `process.env.AGENTS_KEYSTORE_PATH` as a fallback');
    console.log('  inside `createKeystore`. Bridge at your consumer boundary (config-first):');
    console.log(
      '    createKeystore({ customPath: config.keystore?.path ?? process.env.AGENTS_KEYSTORE_PATH })',
    );
    console.log();
  }

  if (trustedServersHits > 0) {
    console.log('Advisory — AGENTS_TRUSTED_SERVERS migration:');
    console.log('  v0.10.0 moves this env-read from `LocalTrustAnchorStore` to a consumer-');
    console.log('  boundary helper. Trust anchors are security-critical posture decisions —');
    console.log('  reading them at the consumer boundary makes the flow auditable. Migration:');
    console.log('    import { resolveTrustedServersFromEnv } from "@abaxxlabs/agents/bootstrap";');
    console.log('    import { LocalTrustAnchorStore } from "@abaxxlabs/agents";');
    console.log('    const initialTrustedServers = resolveTrustedServersFromEnv();');
    console.log(
      '    const store = new LocalTrustAnchorStore({ ownServerDid, initialTrustedServers });',
    );
    console.log();
  }

  if (consumerDomainsHits > 0) {
    console.log('Advisory — AGENTS_CONSUMER_DOMAINS migration:');
    console.log('  The library no longer reads AGENTS_CONSUMER_DOMAINS from env at both');
    console.log('  library sites (org-boundary.ts and auth/generic.ts) — the dual-read');
    console.log(
      '  surface let the two engines drift. Promoted to a single config field. Bridge env at the',
    );
    console.log('  consumer boundary and pass the SAME list to both engines:');
    console.log('    const extra = (process.env.AGENTS_CONSUMER_DOMAINS ?? "").split(",")');
    console.log('      .map(s => s.trim()).filter(Boolean);');
    console.log('    // pass to AgentScope.create config:');
    console.log('    AgentScope.create({ ..., orgBoundary: { extraConsumerDomains: extra } });');
    console.log('    // AND to GenericOidcProvider construction:');
    console.log('    new GenericOidcProvider({ ..., extraConsumerDomains: extra });');
    console.log();
  }

  if (hits.length > 0) {
    console.log('Locations:');
    for (const hit of hits) {
      console.log(`  [${hit.type}] ${hit.file}:${hit.line}: ${hit.snippet}`);
    }
    console.log();
  }

  console.log('This script is read-only. Nothing in your codebase has been modified.');
  console.log('Full migration guide: docs/migrations/byok.md');
}

// ─── Public entrypoint ────────────────────────────────────────────────────────

export async function runMigrateCheck(options: MigrateCheckOptions = {}): Promise<void> {
  const root = path.resolve(options.cwd ?? process.cwd());

  const hits: Hit[] = [];
  walk(root, (filePath) => {
    scanFile(filePath, root, hits);
  });

  const report = categorize(hits);

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          root,
          counts: {
            envReads: hits.filter((h) => h.type === 'env-read').length,
            envWrites: hits.filter((h) => h.type === 'env-write').length,
            configMasterKey: hits.filter((h) => h.type === 'config-master-key').length,
            agentscopeCreate: hits.filter((h) => h.type === 'agentscope-create').length,
            envDevMode: hits.filter((h) => h.type === 'env-dev-mode').length,
            envKeystorePath: hits.filter((h) => h.type === 'env-keystore-path').length,
            envTrustedServers: hits.filter((h) => h.type === 'env-trusted-servers').length,
            envConsumerDomains: hits.filter((h) => h.type === 'env-consumer-domains').length,
          },
          categorization: report,
          hits,
        },
        null,
        2,
      ),
    );
    return;
  }

  printReport(hits, report, root);
}
