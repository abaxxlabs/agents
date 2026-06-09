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
 * Keystore — secure credential storage for agent keys and binding VCs.
 *
 * Platform auto-select: macOS → system keychain via `security` CLI; Linux/CI → JSON file
 * at ~/.agents/keystore.json (0600). JSON writes are atomic (temp file + rename()).
 *
 * macOS: error -25299 (duplicate item) is recoverable via -U flag (upsert).
 * Do NOT fall through to JSON on -25299 — that silently downgrades security.
 *
 * Keychain passwords are never passed as argv: `add-generic-password` uses a
 * trailing `-w` with the secret on stdin; `find-generic-password -w` reads the
 * secret from stdout (no password argv on either path).
 */

import { spawnSync } from 'node:child_process';
import {
  readFileSync,
  mkdirSync,
  renameSync,
  chmodSync,
  existsSync,
  unlinkSync,
  openSync,
  writeSync,
  closeSync,
  statSync,
  constants as fsConstants,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';

// ─── Public interface ────────────────────────────────────────────────────────

/**
 * KeystoreBackend — implement this interface to inject a custom secrets manager.
 *
 * Exported publicly so callers can bring their own backend:
 * AWS Secrets Manager, HashiCorp Vault, Kubernetes secrets, etc.
 * Pass a custom implementation via AgentScopeConfig.keystore.
 */
export interface KeystoreBackend {
  /**
   * Read a stored value by key. Returns null if not found.
   * Must not throw on missing key — return null instead.
   */
  read(key: string): Promise<string | null>;

  /**
   * Write a value under the given key. Overwrites if exists (upsert semantics).
   * Must be atomic where possible — partial writes are worse than no write.
   */
  write(key: string, value: string): Promise<void>;

  /**
   * Delete a stored key. No-op if key does not exist.
   */
  delete(key: string): Promise<void>;
}

type SecurityCliResult = {
  ok: boolean;
  stdout: string;
  stderr: string;
  status: number | null;
  error?: Error;
};

type SecurityCliRunner = (args: string[], stdin?: string | Buffer) => SecurityCliResult;

// ─── macOS Keychain Backend ──────────────────────────────────────────────────

/**
 * MacOS system keychain via the `security` CLI (generic-password items, service='agents').
 *
 * -25299 (errSecDuplicateItem) is recoverable — retry with -U flag (upsert).
 * Never fall through to JSON on -25299; only on non-recoverable errors like -34018.
 */
export class MacOsKeychainBackend implements KeystoreBackend {
  private service: string;
  private logger: Logger;
  private readonly securityCli: SecurityCliRunner;

  constructor(service = 'agents', logger: Logger = getLogger(), securityCli = runSecurityCli) {
    this.service = service;
    this.logger = logger;
    this.securityCli = securityCli;
  }

  async read(key: string): Promise<string | null> {
    const { ok, stdout } = this.securityCli([
      'find-generic-password',
      '-a',
      key,
      '-s',
      this.service,
      '-w',
    ]);
    if (!ok) return null;
    return stdout.trim() || null;
  }

  async write(key: string, value: string): Promise<void> {
    let r = this.securityCli(['add-generic-password', '-a', key, '-s', this.service, '-w'], value);
    if (r.ok) return;

    let stderr = scrubSecret(r.stderr + (r.error?.message ?? ''), value);
    let exitCode = r.status;

    if (stderr.includes('-25299') || exitCode === 45) {
      r = this.securityCli(['add-generic-password', '-U', '-a', key, '-s', this.service, '-w'], value);
      if (r.ok) return;
      stderr = scrubSecret(r.stderr + (r.error?.message ?? ''), value);
      exitCode = r.status;
    }

    this.logger.warn(
      `[agents] Keychain write failed (${exitCode ?? 'unknown'}): ${stderr.trim().substring(0, 100)}. ` +
        'Falling through to JSON keystore. Check keychain permissions.',
      { exitCode, key },
    );
    const msg =
      scrubSecret((r.error?.message ?? '').trim() || stderr.trim() || 'security add-generic-password failed', value);
    const err = new Error(msg) as NodeJS.ErrnoException & { stderr?: string };
    const spawnErr = r.error as NodeJS.ErrnoException | undefined;
    if (spawnErr?.code !== undefined) err.code = spawnErr.code;
    err.stderr = scrubSecret(r.stderr, value);
    throw err;
  }

  async delete(key: string): Promise<void> {
    this.securityCli(['delete-generic-password', '-a', key, '-s', this.service]);
  }
}

// ─── JSON File Backend ───────────────────────────────────────────────────────

/**
 * JSON file keystore — primary backend on Linux and CI.
 * Writes are atomic: temp file + rename(). Values stored as plaintext — macOS prefers keychain.
 */
export class JsonFileBackend implements KeystoreBackend {
  private filePath: string;

  constructor(filePath?: string) {
    this.filePath = filePath ?? join(homedir(), '.agents', 'keystore.json');
  }

  async read(key: string): Promise<string | null> {
    if (!existsSync(this.filePath)) return null;
    try {
      const content = readFileSync(this.filePath, 'utf8');
      const store = JSON.parse(content) as Record<string, string>;
      return store[key] ?? null;
    } catch {
      // Corrupt JSON or read error — treat as empty keystore
      return null;
    }
  }

  async write(key: string, value: string): Promise<void> {
    let store: Record<string, string> = {};
    if (existsSync(this.filePath)) {
      try {
        store = JSON.parse(readFileSync(this.filePath, 'utf8'));
      } catch {
        store = {};
      }
    }

    store[key] = value;

    const dir = dirname(this.filePath);
    mkdirSync(dir, { recursive: true });

    // Temp file in the same directory as the keystore guarantees same-FS rename.
    const tmpPath = join(dir, `.keystore-${randomBytes(8).toString('hex')}.tmp`);
    writeFileExclusive(tmpPath, JSON.stringify(store, null, 2));

    try {
      renameSync(tmpPath, this.filePath);
    } catch {
      try { unlinkSync(tmpPath); } catch { /* best effort */ }
      try { unlinkSync(this.filePath); } catch { /* may not exist */ }
      writeFileExclusive(this.filePath, JSON.stringify(store, null, 2));
    }

    verifyMode(this.filePath);
  }

  async delete(key: string): Promise<void> {
    if (!existsSync(this.filePath)) return;
    let store: Record<string, string> = {};
    try {
      store = JSON.parse(readFileSync(this.filePath, 'utf8'));
    } catch {
      return;
    }
    if (!(key in store)) return;
    delete store[key];

    const dir = dirname(this.filePath);
    mkdirSync(dir, { recursive: true });
    const tmpPath = join(dir, `.keystore-${randomBytes(8).toString('hex')}.tmp`);
    writeFileExclusive(tmpPath, JSON.stringify(store, null, 2));
    try {
      renameSync(tmpPath, this.filePath);
    } catch {
      try { unlinkSync(tmpPath); } catch { /* best effort */ }
      try { unlinkSync(this.filePath); } catch { /* may not exist */ }
      writeFileExclusive(this.filePath, JSON.stringify(store, null, 2));
    }
    verifyMode(this.filePath);
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Options for `createKeystore()`. The library does not read `AGENTS_DEV_MODE` or
 * `AGENTS_KEYSTORE_PATH` — consumers bridge at their own boundary. `CI` is the only env
 * var read internally (universal CI convention, set by every major CI provider).
 */
export interface CreateKeystoreOptions {
  /**
   * Override JSON file path for testing or custom deployments. When omitted,
   * the JsonFileBackend uses its built-in default location.
   *
   * Bridge from config / env at the consumer boundary if you want either
   * source to drive the path. See `AgentScopeConfig.keystore` JSDoc for the
   * recommended config-first precedence.
   */
  customPath?: string;
  /**
   * When `true`, force the JsonFileBackend even on macOS — skips the Keychain
   * prompt that would otherwise block CI runs and dev loops.
   *
   * Bridge from env at the consumer boundary if you want env-driven behavior:
   * `createKeystore({ devMode: process.env.AGENTS_DEV_MODE === 'true' })`.
   */
  devMode?: boolean;
  /** Optional diagnostic logger. */
  logger?: Logger;
}

/**
 * Create the appropriate keystore backend for the current platform.
 *
 * macOS (non-CI, non-devMode): MacOsKeychainBackend. CI or devMode: JsonFileBackend.
 * `CI=true` is set by every major CI provider — no need for consumers to forward devMode.
 */
export function createKeystore(opts: CreateKeystoreOptions = {}): KeystoreBackend {
  const isMac = process.platform === 'darwin';
  const isCI = process.env.CI === 'true' || opts.devMode === true;

  if (isMac && !isCI) {
    return new MacOsKeychainBackend('agents', opts.logger);
  }

  return new JsonFileBackend(opts.customPath);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// O_EXCL prevents symlink attacks and ensures the file never exists with wider permissions.
function writeFileExclusive(filePath: string, data: string): void {
  const fd = openSync(
    filePath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    writeSync(fd, data);
  } finally {
    closeSync(fd);
  }
}

function verifyMode(filePath: string): void {
  try {
    const st = statSync(filePath);
    if ((st.mode & 0o777) !== 0o600) chmodSync(filePath, 0o600);
  } catch { /* best effort */ }
}

const OSX_SECURITY_CLI = '/usr/bin/security';
const SECURITY_CLI_TIMEOUT_MS = 5000;

// Defense-in-depth: macOS `security` does not echo passwords today, but if a future
// flag or version did, we strip the literal secret from any string we surface in
// warnings, thrown errors, or attached `stderr` properties.
function scrubSecret(text: string, secret: string): string {
  if (!text || !secret) return text;
  return text.split(secret).join('[REDACTED]');
}

function runSecurityCli(
  args: string[],
  stdin?: string | Buffer,
): SecurityCliResult {
  const result = spawnSync(OSX_SECURITY_CLI, args, {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    timeout: SECURITY_CLI_TIMEOUT_MS,
    ...(stdin !== undefined ? { input: stdin } : {}),
  });
  const stderr = result.stderr?.toString() ?? '';
  if (result.error) {
    return {
      ok: false,
      stdout: '',
      stderr,
      status: result.status,
      error: result.error,
    };
  }
  const stdout =
    result.stdout === null || result.stdout === undefined ? '' : String(result.stdout);
  return {
    ok: result.status === 0,
    stdout,
    stderr,
    status: result.status,
  };
}
