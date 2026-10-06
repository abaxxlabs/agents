#!/usr/bin/env node

/**
 * Asserts that every artifact path named in package.json metadata
 * (main, module, types, exports, bin) exists on disk after a clean build.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import path, { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Validates one exact path or compact glob from forbiddenPaths.
function assertValidPolicyRule(rule, index) {
  const label = `forbiddenPaths[${index}]`;
  if (typeof rule !== 'string') throw new Error(`${label} must be a string`);
  if (!rule || rule !== rule.trim()) {
    throw new Error(`${label} must be a non-empty path without surrounding whitespace`);
  }
  if (/\p{Cc}/u.test(rule)) throw new Error(`${label} contains a control character`);
  if (rule.includes('\\')) throw new Error(`${label} must use forward slashes`);
  if (path.posix.isAbsolute(rule) || /^[A-Za-z]:/.test(rule)) {
    throw new Error(`${label} must be repository-relative`);
  }
  if (rule.startsWith('./') || rule.endsWith('/') || rule.includes('//')) {
    throw new Error(`${label} is not a normalized repository-relative path`);
  }
  if (rule.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error(`${label} cannot contain "." or ".." segments`);
  }
  if (/[?\[\]{}!]/.test(rule)) throw new Error(`${label} uses an unsupported glob token`);
  for (const segment of rule.split('/')) {
    if (segment.includes('**') && segment !== '**') {
      throw new Error(`${label} must use "**" as a complete path segment`);
    }
  }
}

function assertStringArray(value, field) {
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || !entry.trim() || entry !== entry.trim()) {
      throw new Error(
        `${field}[${index}] must be a non-empty string without surrounding whitespace`,
      );
    }
    return entry;
  });
}

function parseBlockedTerms(value = []) {
  if (!Array.isArray(value)) throw new Error('blockedTerms must be an array');
  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`blockedTerms[${index}] must be an object`);
    }
    const [term] = assertStringArray([entry.term], `blockedTerms[${index}].term`);
    const [pattern] = assertStringArray([entry.pattern], `blockedTerms[${index}].pattern`);
    try {
      new RegExp(pattern, 'i');
    } catch (error) {
      throw new Error(
        `blockedTerms[${index}].pattern is invalid: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    return Object.freeze({ term, pattern: new RegExp(pattern, 'i') });
  });
}

/** Parses and validates the public repository policy schema. */
export function parsePublicRepoPolicy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('public repository policy must be a JSON object');
  }
  const supportedFields = new Set([
    'forbiddenPaths',
    'licenseSourceDirectories',
    'ticketPrefixes',
    'blockedTerms',
  ]);
  for (const field of Object.keys(value)) {
    if (!supportedFields.has(field)) {
      throw new Error(`public repository policy contains unknown field "${field}"`);
    }
  }
  if (!Object.hasOwn(value, 'forbiddenPaths')) {
    throw new Error('public repository policy must contain forbiddenPaths');
  }
  if (!Array.isArray(value.forbiddenPaths)) throw new Error('forbiddenPaths must be an array');
  if (value.forbiddenPaths.length === 0) throw new Error('forbiddenPaths must not be empty');

  const seen = new Set();
  value.forbiddenPaths.forEach((rule, index) => {
    assertValidPolicyRule(rule, index);
    if (seen.has(rule)) throw new Error(`forbiddenPaths contains duplicate rule "${rule}"`);
    seen.add(rule);
  });
  return Object.freeze({
    forbiddenPaths: Object.freeze([...value.forbiddenPaths]),
    licenseSourceDirectories: Object.freeze(
      assertStringArray(value.licenseSourceDirectories ?? ['src/'], 'licenseSourceDirectories'),
    ),
    ticketPrefixes: Object.freeze(assertStringArray(value.ticketPrefixes ?? [], 'ticketPrefixes')),
    blockedTerms: Object.freeze(parseBlockedTerms(value.blockedTerms)),
  });
}

/** Loads a policy file and rejects invalid schema or path rules. */
export function loadPublicRepoPolicy(policyPath) {
  if (!policyPath) throw new Error('public repository policy path is required');
  let value;
  try {
    value = JSON.parse(readFileSync(policyPath, 'utf8'));
  } catch (error) {
    throw new Error(
      `failed to read public repository policy: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return parsePublicRepoPolicy(value);
}

function globToRegExp(glob) {
  let source = '^';
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    const next = glob[index + 1];
    if (char === '*' && next === '*') {
      const after = glob[index + 2];
      if (after === '/') {
        source += '(?:.*\\/)?';
        index += 2;
      } else {
        source += '.*';
        index += 1;
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else {
      source += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
  }
  return new RegExp(`${source}$`);
}

const globCache = new Map();

function matchesGlob(filePath, glob) {
  let regexp = globCache.get(glob);
  if (!regexp) {
    regexp = globToRegExp(glob);
    globCache.set(glob, regexp);
  }
  return regexp.test(filePath);
}

/** Returns the first policy glob that matches a repository-relative path. */
export function firstMatchingGlob(filePath, globs) {
  return globs.find((glob) => matchesGlob(filePath, glob));
}

/** Normalizes one candidate path for policy and filesystem checks. */
export function normalizeArtifactPath(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return { path: '', error: 'empty artifact path' };
  const slashPath = trimmed.replace(/\\/g, '/').replace(/^\.\//, '');
  if (path.posix.isAbsolute(slashPath)) {
    return { path: slashPath, error: 'artifact paths must be relative' };
  }
  const normalized = path.posix.normalize(slashPath);
  if (normalized === '.' || normalized.startsWith('../') || normalized === '..') {
    return { path: normalized, error: 'artifact path escapes the artifact root' };
  }
  return { path: normalized };
}

/** Normalizes candidate paths, removes duplicates, and collects invalid inputs. */
export function normalizeArtifactPaths(paths) {
  const normalized = [];
  const violations = [];
  const seen = new Set();
  for (const input of paths) {
    const result = normalizeArtifactPath(input);
    if (result.error) {
      violations.push({ path: result.path || String(input ?? ''), reason: result.error });
    } else if (!seen.has(result.path)) {
      seen.add(result.path);
      normalized.push(result.path);
    }
  }
  return { paths: normalized, violations };
}

/** Returns whether a path is publishable and the first rule that rejects it. */
export function evaluatePublicRepoPath(filePath, policy) {
  if (!policy)
    throw new Error('public repository policy is required to evaluate publication paths');
  const normalized = normalizeArtifactPath(filePath);
  if (normalized.error || normalized.path !== filePath) {
    throw new Error(
      `evaluated path "${filePath}" must be a normalized repository-relative path${
        normalized.error ? `: ${normalized.error}` : ''
      }`,
    );
  }
  const matchedRule = firstMatchingGlob(filePath, policy.forbiddenPaths) ?? null;
  return { path: filePath, allowed: matchedRule === null, matchedRule };
}

const args = process.argv.slice(2);
const FORBIDDEN_PACKAGE_ARTIFACTS = [
  './dist/mcp/rest-bridge.js',
  './dist/mcp/rest-bridge.js.map',
  './dist/mcp/rest-bridge.d.ts',
  './dist/mcp/rest-bridge.d.ts.map',
  './dist/cjs/mcp/rest-bridge.js',
  './dist/cjs/mcp/rest-bridge.js.map',
];

const packageJsonPath = resolve(process.cwd(), args[0] ?? 'package.json');
const packageRoot = dirname(packageJsonPath);

function readPackageJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    console.error(`[package-artifacts] Failed to read ${path}: ${formatError(err)}`);
    process.exit(1);
  }
}

function formatError(err) {
  return err instanceof Error ? err.message : String(err);
}

function pathSegment(base, key) {
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `${base}.${key}` : `${base}[${JSON.stringify(key)}]`;
}

function addPackagePath(checks, metadataPath, packagePath) {
  if (typeof packagePath !== 'string' || packagePath.length === 0) return;

  checks.push({
    metadataPath,
    packagePath,
    filePath: resolve(packageRoot, packagePath),
  });
}

function walkExports(checks, value, metadataPath) {
  if (typeof value === 'string') {
    addPackagePath(checks, metadataPath, value);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      walkExports(checks, item, `${metadataPath}[${index}]`);
    });
    return;
  }

  if (!value || typeof value !== 'object') return;

  for (const [key, nested] of Object.entries(value)) {
    walkExports(checks, nested, pathSegment(metadataPath, key));
  }
}

function collectMetadataPaths(pkg) {
  const checks = [];

  addPackagePath(checks, 'main', pkg.main);
  addPackagePath(checks, 'module', pkg.module);
  addPackagePath(checks, 'types', pkg.types);

  if (pkg.exports !== undefined) {
    walkExports(checks, pkg.exports, 'exports');
  }

  if (typeof pkg.bin === 'string') {
    addPackagePath(checks, 'bin', pkg.bin);
  } else if (pkg.bin && typeof pkg.bin === 'object') {
    for (const [name, target] of Object.entries(pkg.bin)) {
      addPackagePath(checks, pathSegment('bin', name), target);
    }
  }

  return checks;
}

function isExistingFile(path) {
  try {
    return existsSync(path) && statSync(path).isFile();
  } catch {
    return false;
  }
}

// Verifies built package entrypoints and forbidden historical outputs.
function runPackageArtifactCli() {
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node scripts/assert-package-artifacts.mjs [package.json]');
    return 0;
  }

  const pkg = readPackageJson(packageJsonPath);
  const checks = collectMetadataPaths(pkg);
  const missing = checks.filter((check) => !isExistingFile(check.filePath));
  const forbidden = FORBIDDEN_PACKAGE_ARTIFACTS.map((packagePath) => ({
    packagePath,
    filePath: resolve(packageRoot, packagePath),
  })).filter((check) => isExistingFile(check.filePath));

  if (missing.length > 0) {
    console.error(
      `[package-artifacts] ${missing.length} package metadata path(s) point at missing files:`,
    );
    for (const check of missing) {
      console.error(`- ${check.metadataPath}: ${check.packagePath} -> ${check.filePath}`);
    }
    return 1;
  }

  if (forbidden.length > 0) {
    console.error(
      '[package-artifacts] Historical REST bridge artifact(s) must not be emitted or packed:',
    );
    for (const check of forbidden) {
      console.error(`- ${check.packagePath} -> ${check.filePath}`);
    }
    return 1;
  }

  console.log(
    `[package-artifacts] OK: ${checks.length} package metadata path(s) exist; historical REST bridge artifacts absent.`,
  );
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = runPackageArtifactCli();
}
