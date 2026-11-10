import { readdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import {
  asMasterKey, createStorageBackend, deriveSessionMacKey, generateDidKey,
  issueCredential, verifyJwtSignature,
} from '@abaxxlabs/agents';
import { AgentScope } from '@abaxxlabs/agents/sql';

export const BASE_COLUMNS = ['id', 'instrument', 'quantity', 'price'];
export const BASE_SQL = 'SELECT id, instrument, quantity, price FROM orders ORDER BY id';
export const BROAD_SQL = 'SELECT id, instrument, quantity, price, counterparty FROM orders ORDER BY id';
const silentLogger = Object.freeze({ warn() {}, error() {} });
const proofDirectory = dirname(fileURLToPath(import.meta.url));
let sdkPackage;
let provenance;

function packageInfo(entry, name) {
  let directory = dirname(entry);
  for (let depth = 0; depth < 8; depth++) {
    try {
      const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
      if (manifest.name === name) return { version: manifest.version, packageRoot: directory, entry };
    } catch { /* Package exports can hide manifests; inspect the resolved entry's ancestors. */ }
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error('Resolved package manifest unavailable');
}

function loadedSdkPackage() {
  sdkPackage ??= packageInfo(fileURLToPath(import.meta.resolve('@abaxxlabs/agents')), '@abaxxlabs/agents');
  return sdkPackage;
}

function safeSourceFrame(error) {
  let sdkDist;
  try { sdkDist = join(loadedSdkPackage().packageRoot, 'dist'); } catch { /* Local proof frames remain useful. */ }
  if (typeof error?.stack !== 'string') return null;
  for (const frame of error.stack.split('\n').slice(1, 30)) {
    const match = /^\s*at (?:.* \()?(?:async )?((?:file:\/\/\/|\/)[^\n()]+):(\d{1,9}):\d+\)?$/.exec(frame);
    if (!match) continue;
    let path;
    try { path = match[1].startsWith('file:') ? fileURLToPath(match[1]) : resolve(match[1]); } catch { continue; }
    const local = relative(proofDirectory, path);
    if (['runtime.mjs', 'scenarios.mjs', 'worker.mjs'].includes(local)) return { file: local, line: Number(match[2]) };
    if (sdkDist && path.startsWith(`${sdkDist}${sep}`)) {
      const sdkFile = relative(sdkDist, path).split(sep).join('/');
      if (/^(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+\.m?js$/.test(sdkFile)) {
        return { file: `SDK/dist/${sdkFile}`, line: Number(match[2]) };
      }
    }
  }
  return null;
}

function runtimeProvenance() {
  if (provenance) return provenance;
  provenance = { nodeAbi: process.versions.modules ?? null, uid: process.getuid?.() ?? null };
  try {
    const header = process.report.getReport().header;
    provenance.glibc = { runtime: header.glibcVersionRuntime ?? null, compiler: header.glibcVersionCompiler ?? null };
  } catch (error) { provenance.glibc = { error: safeError(error) }; }
  try { provenance.sdk = loadedSdkPackage(); }
  catch (error) { provenance.sdk = { error: safeError(error) }; }
  try {
    const requireFromSdk = createRequire(join(dirname(loadedSdkPackage().entry), 'storage', 'sqlite', 'index.js'));
    provenance.betterSqlite3 = packageInfo(requireFromSdk.resolve('better-sqlite3'), 'better-sqlite3');
    const Database = requireFromSdk('better-sqlite3');
    let database;
    try {
      database = new Database(':memory:');
      provenance.betterSqlite3.sqliteVersion = database.prepare('SELECT sqlite_version() AS version').get().version;
    } finally { database?.close(); }
    provenance.betterSqlite3.probe = 'PASS';
  } catch (error) {
    provenance.betterSqlite3 = { ...provenance.betterSqlite3, probe: 'FAIL', error: safeError(error) };
  }
  const lockPath = fileURLToPath(new URL('../../package-lock.json', import.meta.url));
  try {
    provenance.imagePackageLock = { path: lockPath, sha256: createHash('sha256').update(readFileSync(lockPath)).digest('hex') };
  } catch (error) { provenance.imagePackageLock = { path: lockPath, error: safeError(error) }; }
  return provenance;
}

export const LIMITATIONS = [
  'The proof wrapper rejects new work and drains tracked operations; SDK AgentScope.query itself has no closed-state guard.',
  'SDK close does not close injected storage or pools; this caller closes SQLite explicitly and the worker closes process pools.',
  'Only caller-owned master, session-MAC, and owner-private-key buffers are explicitly overwritten and checked.',
  'Opaque agent signers, SDK-loaded column keys, temporary crypto copies, and immutable credential/env strings cannot be proven erased by these public APIs.',
  'Process-global JWT imported-key caches can retain keys after runtime close (currently bounded to 256 entries per cache).',
  'Audit verifyRecord checks JWT signatures and matches signed payload fields to the supplied record; the proof also compares covered fields and checks unfiltered chains.',
  'For the query/rejection records exercised here, audit signatures do not cover previousHash/version/status/reason/reasonCode; hash-chain validation is separate and cannot prove absence of deleted rows.',
  'The fixed workload serializes each runtime and separates audit timestamps; same-millisecond concurrent chain-head ordering is outside this proof.',
  'Memory slopes and resource snapshots are observational; garbage collection, native allocators, and key-cache warmup prevent a universal RSS threshold.',
  'Restart non-recovery requires the orchestrator to observe SIGKILL and launch restart against the same PostgreSQL fixture.',
];

export class ProofFailure extends Error {
  constructor(check) {
    super('Proof check failed');
    this.name = 'ProofFailure';
    this.check = check;
  }
}

export function check(checks, name, passed, details = {}) {
  checks.push({ name, status: passed ? 'PASS' : 'FAIL', ...details });
  if (!passed) throw new ProofFailure(name);
}

export function safeError(error) {
  const codes = new Set([
    '42501', '42P01', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT',
    'CREDENTIAL_INVALID', 'CREDENTIAL_REVOKED', 'CREDENTIAL_REPLAYED',
    'SCOPE_VIOLATION', 'QUERY_REJECTED', 'PROOF_RUNTIME_CLOSED',
    'MASTER_KEY_MISMATCH', 'DB_CONNECTION_FAILED', 'SQLITE_RUNTIME_UNAVAILABLE',
    'CREDENTIAL_MALFORMED', 'CREDENTIAL_EXPIRED', 'AUDIT_WRITE_FAILED', 'UNKNOWN_ISSUER',
    'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_DLOPEN_FAILED', 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    'SQLITE_ERROR', 'SQLITE_MISUSE', 'SQLITE_BUSY', 'SQLITE_CONSTRAINT', 'SQLITE_CANTOPEN',
  ]);
  const names = new Set(['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'URIError', 'AggregateError',
    'ProofFailure', 'AgentScopeError', 'CredentialInvalidError', 'CredentialExpiredError', 'CredentialRevokedError',
    'CredentialMalformedError', 'CredentialReplayedError', 'UnknownIssuerError', 'ScopeViolationError',
    'QueryRejectedError', 'MasterKeyMismatchError', 'DbConnectionFailedError', 'SqliteRuntimeUnavailableError',
    'AuditWriteFailedError', 'DecryptionFailedError', 'SqliteError']);
  return { category: error instanceof ProofFailure ? 'check-failed' : 'operation-failed',
    name: names.has(error?.name) ? error.name : 'REDACTED', code: codes.has(error?.code) ? error.code : 'REDACTED',
    source: safeSourceFrame(error), message: 'Details suppressed to protect credentials and fixture values' };
}

export function poolSnapshot(pool, max) {
  return { max, total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount };
}

export async function snapshot(context, phase, cycle = 0) {
  const resources = {};
  for (const name of process.getActiveResourcesInfo()) resources[name] = (resources[name] ?? 0) + 1;
  let fileDescriptors = null;
  if (process.platform === 'linux') {
    try { fileDescriptors = (await readdir('/proc/self/fd')).length; } catch { /* procfs is optional. */ }
  }
  return { phase, cycle, elapsedMs: performance.now() - context.startedAt,
    memoryUsage: process.memoryUsage(), activeResources: resources, fileDescriptors,
    pools: { query: poolSnapshot(context.queryPool, 2), raw: poolSnapshot(context.rawPool, 1) },
    runtimes: context.manager.summary() };
}

export function runtimeDescription() {
  return { node: process.version, platform: process.platform, architecture: process.arch,
    ...runtimeProvenance(),
    sqlite: ':memory:', sqliteDriver: process.versions.bun ? 'bun:sqlite' : 'better-sqlite3',
    storageOwnership: 'callerOwned', poolOwnership: 'workerOwned/shared',
    identity: 'locally generated did:key owners and real Ed25519-signed credentials; no human login',
    limitations: LIMITATIONS,
    sources: [
      'https://github.com/abaxxlabs/agents/blob/main/src/sql/agent-scope.ts',
      'https://github.com/abaxxlabs/agents/blob/main/src/audit/logger.ts',
      'https://github.com/abaxxlabs/agents/blob/main/src/crypto/jwt.ts',
      'https://node-postgres.com/apis/pool',
      'https://nodejs.org/api/process.html#processversions',
      'https://nodejs.org/api/report.html#reportgetreporterr',
    ] };
}

class ProofRuntime {
  constructor(manager, label) {
    this.manager = manager;
    this.label = label;
    this.closed = false;
    this.inFlight = new Set();
    this.queryTail = Promise.resolve();
    this.lastQueryFinished = 0;
    this.buffers = [];
  }

  track(operation) {
    if (this.closed) {
      const error = new Error('Proof runtime closed');
      error.code = 'PROOF_RUNTIME_CLOSED';
      return Promise.reject(error);
    }
    const pending = Promise.resolve().then(operation);
    this.inFlight.add(pending);
    pending.then(() => this.inFlight.delete(pending), () => this.inFlight.delete(pending));
    return pending;
  }

  async initialize(masterKey) {
    this.masterKey = asMasterKey(Buffer.from(masterKey));
    this.buffers.push(this.masterKey);
    this.macKey = deriveSessionMacKey(this.masterKey);
    this.buffers.push(this.macKey);
    this.owner = generateDidKey();
    this.buffers.push(this.owner.privateKey);
    this.storage = await createStorageBackend({ type: 'sqlite', path: ':memory:', sessionMacKey: this.macKey });
    this.manager.storesCreated++;
    await this.storage.initialize();
    this.initialCounts = await this.counts();
    this.scope = await AgentScope.create({
      database: { connectionString: this.manager.connectionString, poolSize: 2 },
      devMode: true, scopeMode: 'projection', audit: { enabled: true },
    }, { pool: this.manager.pool, storage: this.storage, masterKey: this.masterKey, logger: silentLogger });
    this.manager.scopesCreated++;
    const ownership = this.scope.toJSON();
    this.callerOwned = ownership.ownsStorage === false && ownership.ownsPool === false;
  }

  async counts() {
    return { agents: await this.storage.agents.count(), audit: await this.storage.audit.count(),
      revocations: (await this.storage.revocation.loadAll()).length };
  }

  populate() {
    return this.track(async () => {
      this.agent = await this.scope.createAgentIdentity({ name: `Proof ${this.label}`, ownerDid: this.owner.did });
      const issue = (columns) => issueCredential(this.owner.did, this.owner.privateKey, {
        agent: this.agent.did, columns: columns.map((column) => `orders.${column}`), actions: ['read'], expiresIn: '1h',
      });
      this.credential = await issue(BASE_COLUMNS);
      this.broadCredential = await issue([...BASE_COLUMNS, 'counterparty']);
    });
  }

  query({ credential = this.credential, sql = BASE_SQL, agent = this.agent?.did, requirePresentation = false } = {}) {
    const previous = this.queryTail;
    const pending = this.track(async () => {
      await previous;
      // SQLite chain-head ordering uses timestamps, so the fixed workload avoids millisecond ties.
      while (Date.now() <= this.lastQueryFinished) await delay(1);
      try { return await this.scope.query({ agent, credential, table: 'orders', sql, requirePresentation }); }
      finally { this.lastQueryFinished = Date.now(); }
    });
    this.queryTail = pending.then(() => undefined, () => undefined);
    return pending;
  }

  close(options = {}) {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.closePromise = this.dispose(options);
    return this.closePromise;
  }

  async dispose({ characterizeSdk = false } = {}) {
    const errors = [];
    const attempt = async (operation) => {
      try { return await operation(); } catch (error) { errors.push(error); return undefined; }
    };
    const draining = this.inFlight.size;
    await Promise.allSettled([...this.inFlight]);
    const retained = characterizeSdk && this.agent
      ? { scope: this.scope, signer: this.agent.signer, publicKey: this.agent.publicKey,
        agent: this.agent.did, credential: this.credential } : null;
    const result = { draining, callerOwned: this.callerOwned ?? true };
    try {
      if (this.scope) await attempt(() => this.scope.close());
      if (retained) {
        result.storageAccessibleAfterSdkClose = (await attempt(() => this.storage.agents.count())) === 1;
        result.poolAccessibleAfterSdkClose = !!(await attempt(() => this.manager.pool.query('SELECT 1')));
        while (Date.now() <= this.lastQueryFinished) await delay(1);
        try {
          const stale = await retained.scope.query({ agent: retained.agent, credential: retained.credential,
            table: 'orders', sql: BASE_SQL });
          result.sdkQueryAfterClose = stale.rows.length === 2 ? 'succeeded' : 'unexpected-result';
        } catch (error) { result.sdkQueryAfterClose = 'rejected'; result.sdkQueryError = safeError(error); }
        const jwt = await attempt(() => retained.signer.signJwt({ aud: 'proof-stale-signer', iat: 1 }));
        result.retainedSignerUsable = jwt ? await attempt(() => verifyJwtSignature(jwt, retained.publicKey)) : false;
        const logger = retained.scope.auditLoggerInstance;
        const chain = await attempt(() => logger.verifyAuditChain());
        const records = await attempt(() => logger.export());
        let signaturesValid = !!records;
        for (const record of records ?? []) signaturesValid &&= await attempt(() => logger.verifyRecord(record, retained.publicKey));
        result.auditAfterSdkClose = { chainOk: chain?.ok === true, partial: chain?.partial,
          totalRecords: chain?.totalRecords, signaturesValid };
      }
    } finally {
      if (this.storage) {
        await attempt(async () => { await this.storage.close(); this.manager.storesClosed++; this.storage = null; });
      }
      for (const buffer of this.buffers) buffer.fill(0);
      result.callerOwnedBuffersZeroed = this.buffers.every((buffer) => buffer.every((byte) => byte === 0));
      this.manager.buffersZeroed &&= result.callerOwnedBuffersZeroed;
      this.scope = null;
      this.agent = null;
      this.owner = null;
      this.credential = null;
      this.broadCredential = null;
      if (!this.storage) { this.manager.live.delete(this); this.manager.closed++; }
    }
    if (errors.length) throw new AggregateError(errors, 'Runtime cleanup failed');
    return result;
  }
}

export function createRuntimeManager(pool, connectionString) {
  return {
    pool, connectionString, live: new Set(), created: 0, closed: 0,
    storesCreated: 0, storesClosed: 0, scopesCreated: 0, buffersZeroed: true,
    async create(masterKey, label) {
      const runtime = new ProofRuntime(this, label);
      this.live.add(runtime);
      this.created++;
      try { await runtime.initialize(masterKey); return runtime; }
      catch (error) {
        try { await runtime.close(); } catch { /* Worker cleanup still accounts for any live store. */ }
        throw error;
      }
    },
    summary() {
      return { live: this.live.size, created: this.created, closed: this.closed,
        scopesCreated: this.scopesCreated, storesCreated: this.storesCreated, storesClosed: this.storesClosed,
        inFlight: [...this.live].reduce((sum, runtime) => sum + runtime.inFlight.size, 0),
        callerOwnedBuffersZeroed: this.buffersZeroed };
    },
    async closeAll() {
      const results = await Promise.allSettled([...this.live].map(async (runtime) => {
        try { await runtime.close(); }
        catch (error) {
          if (runtime.storage) {
            await runtime.storage.close();
            runtime.storage = null;
            this.storesClosed++;
            this.live.delete(runtime);
            this.closed++;
          }
          throw error;
        }
      }));
      if (results.some((result) => result.status === 'rejected')) throw new Error('Runtime cleanup failed');
    },
  };
}
