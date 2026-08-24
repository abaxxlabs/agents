#!/usr/bin/env node
/**
 * npm cache ownership guard for release verification.
 *
 * The release path must use the maintainer's normal npm cache unless CI
 * deliberately provides an isolated runner-owned cache. A root-owned npm cache
 * fails later inside `npm pack`, `npm publish --dry-run`, or smoke installs
 * with npm's generic cache error; this guard makes the failure immediate and
 * tells the operator exactly which cache path needs repair.
 */

import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, mkdir, opendir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function expandHome(cachePath) {
  if (cachePath === '~') return os.homedir();
  if (cachePath.startsWith(`~${path.sep}`) || cachePath.startsWith('~/')) {
    return path.join(os.homedir(), cachePath.slice(2));
  }
  return cachePath;
}

export function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export async function resolveNpmCachePath(env = process.env) {
  const configured = env.npm_config_cache ?? env.NPM_CONFIG_CACHE;
  if (configured) return path.resolve(expandHome(configured));

  const { stdout } = await execFileAsync('npm', ['config', 'get', 'cache'], {
    env,
    maxBuffer: 1024 * 1024,
  });
  const cachePath = stdout.trim();
  if (!cachePath || cachePath === 'undefined' || cachePath === 'null') {
    throw new Error('Unable to resolve npm cache path from `npm config get cache`.');
  }
  return path.resolve(expandHome(cachePath));
}

async function firstNonOwnedEntry(cachePath, expectedUid) {
  const stack = [cachePath];

  while (stack.length > 0) {
    const current = stack.pop();
    let stats;
    try {
      stats = await lstat(current);
    } catch (error) {
      return { path: current, error, reason: 'stat' };
    }

    if (stats.uid !== expectedUid) {
      return {
        path: current,
        uid: stats.uid,
        gid: stats.gid,
        reason: 'ownership',
      };
    }

    if (!stats.isDirectory()) continue;

    let dir;
    try {
      dir = await opendir(current);
    } catch (error) {
      return { path: current, error, reason: 'read' };
    }

    for await (const entry of dir) {
      stack.push(path.join(current, entry.name));
    }
  }

  return null;
}

export async function validateNpmCache(cachePath, options = {}) {
  const expectedUid = options.expectedUid ?? process.getuid?.();
  const expectedGid = options.expectedGid ?? process.getgid?.();
  const resolvedCachePath = path.resolve(expandHome(cachePath));

  let rootStats;
  try {
    rootStats = await lstat(resolvedCachePath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      return {
        ok: false,
        code: 'stat',
        cachePath: resolvedCachePath,
        expectedUid,
        expectedGid,
        error,
      };
    }

    try {
      await mkdir(resolvedCachePath, { recursive: true });
      rootStats = await lstat(resolvedCachePath);
    } catch (createError) {
      return {
        ok: false,
        code: 'create',
        cachePath: resolvedCachePath,
        expectedUid,
        expectedGid,
        error: createError,
      };
    }
  }

  if (!rootStats.isDirectory()) {
    return {
      ok: false,
      code: 'not-directory',
      cachePath: resolvedCachePath,
      expectedUid,
      expectedGid,
      actualUid: rootStats.uid,
      actualGid: rootStats.gid,
    };
  }

  const probePath = path.join(
    resolvedCachePath,
    `.agents-npm-cache-check-${process.pid}-${Date.now()}`,
  );
  try {
    await access(resolvedCachePath, constants.R_OK | constants.W_OK | constants.X_OK);
    await writeFile(probePath, 'ok\n', { flag: 'wx' });
  } catch (error) {
    return {
      ok: false,
      code: 'writable',
      cachePath: resolvedCachePath,
      expectedUid,
      expectedGid,
      actualUid: rootStats.uid,
      actualGid: rootStats.gid,
      error,
    };
  } finally {
    await rm(probePath, { force: true }).catch(() => {});
  }

  if (expectedUid !== undefined) {
    const firstMismatch = await firstNonOwnedEntry(resolvedCachePath, expectedUid);
    if (firstMismatch) {
      return {
        ok: false,
        code: firstMismatch.reason === 'ownership' ? 'ownership' : 'inspect',
        cachePath: resolvedCachePath,
        expectedUid,
        expectedGid,
        entry: firstMismatch,
      };
    }
  }

  return {
    ok: true,
    cachePath: resolvedCachePath,
    expectedUid,
    expectedGid,
  };
}

export function formatNpmCacheFailure(result) {
  const lines = [
    'ERROR: npm cache ownership/writability check failed before release verification.',
    `Cache path: ${result.cachePath}`,
  ];

  if (result.expectedUid !== undefined) {
    lines.push(
      `Current user: uid=${result.expectedUid}${
        result.expectedGid !== undefined ? ` gid=${result.expectedGid}` : ''
      }`,
    );
  }

  if (result.code === 'ownership' && result.entry) {
    lines.push(
      `First non-owned entry: ${result.entry.path}`,
      `Entry owner: uid=${result.entry.uid} gid=${result.entry.gid}`,
    );
  } else if (result.code === 'not-directory') {
    lines.push('The configured npm cache path exists but is not a directory.');
  } else if (result.code === 'inspect' && result.entry) {
    lines.push(
      `Could not inspect npm cache entry: ${result.entry.path}`,
      `Reason: ${result.entry.error?.message ?? 'unknown error'}`,
    );
  } else if (result.error) {
    lines.push(`Reason: ${result.error.message}`);
  }

  lines.push(
    '',
    'Fix for maintainer machines:',
    `  sudo chown -R "$(id -u):$(id -g)" ${shellQuote(result.cachePath)}`,
    `  chmod -R u+rwX ${shellQuote(result.cachePath)}`,
    '',
    'CI should set npm_config_cache to a runner-owned directory before any npm release command runs.',
  );

  return lines.join('\n');
}

function parseArgs(argv) {
  const args = { cachePath: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--cache') {
      const value = argv[i + 1];
      if (!value) throw new Error('--cache requires a path');
      args.cachePath = value;
      i += 1;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

export async function runCli(argv = process.argv.slice(2), env = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('Usage: node scripts/check-npm-cache.mjs [--cache <path>]');
    return 0;
  }

  const cachePath = args.cachePath ?? (await resolveNpmCachePath(env));
  const result = await validateNpmCache(cachePath);
  if (!result.ok) {
    console.error(formatNpmCacheFailure(result));
    return 1;
  }

  console.log(`npm cache OK: ${result.cachePath}`);
  return 0;
}

const isMain = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;

if (isMain) {
  runCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
