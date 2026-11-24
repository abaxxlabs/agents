import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { spawnSync } from 'node:child_process';

import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSandboxExecutors } from '../demo/playground/src/sandbox-executor.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const playgroundRoot = join(repoRoot, 'demo', 'playground');
const DB_URL =
  process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:54322/postgres';
const MASTER_KEY = 'ab'.repeat(32);

interface SandboxRow {
  sandbox_id: string;
  id: number;
  instrument: string;
  side: string;
  quantity: unknown;
  price: unknown;
  counterparty: unknown;
  status: string;
}

interface DeleteEvent {
  sandbox_id: string;
  id: number;
}

interface Snapshot {
  privateRows: SandboxRow[];
  deleteEvents: DeleteEvent[];
  fixtureFingerprint: string;
}

async function isPostgresReachable(): Promise<boolean> {
  const p = new pg.Pool({ connectionString: DB_URL, max: 1, connectionTimeoutMillis: 2000 });
  try {
    await p.query('SELECT 1');
    await p.end();
    return true;
  } catch {
    await p.end().catch(() => undefined);
    return false;
  }
}

const postgresReachable = await isPostgresReachable();
// Missing build/dependencies skip locally but fail in the dedicated sandbox CI job.
const playgroundDepsInstalled = existsSync(join(playgroundRoot, 'node_modules', 'pg'));
const requireSuite = process.env.SANDBOX_PLANE_SUITE === 'required';
const distEntryPoints = [
  join(repoRoot, 'dist', 'index.js'),
  join(repoRoot, 'dist', 'sql', 'index.js'),
];
const distBuilt = distEntryPoints.every((p) => existsSync(p));

function suiteMode(): 'run' | 'skip' {
  if (postgresReachable && playgroundDepsInstalled && distBuilt) return 'run';
  if (!requireSuite) return 'skip';
  const missing = [
    !postgresReachable ? 'a reachable Postgres at DATABASE_URL' : null,
    !playgroundDepsInstalled ? 'demo/playground/node_modules (npm ci in demo/playground)' : null,
    !distBuilt ? 'the root dist/ build (npm run build)' : null,
  ].filter((v) => v !== null);
  throw new Error(
    `the shared sandbox data plane suite cannot run — missing: ${missing.join('; ')}`,
  );
}

const describeFn = suiteMode() === 'skip' ? describe.skip : describe;

const SANDBOX_A = 'a1a1a1a1-0000-4000-8000-000000000001';
const SANDBOX_B = 'b2b2b2b2-0000-4000-8000-000000000002';

const SEED: Record<number, [number, number]> = {
  1: [12.45, 500],
  2: [12.8, 250],
  3: [3.215, 1000],
  4: [88.1, 750],
  5: [13.05, 400],
  6: [3.41, 600],
  7: [86.75, 320],
  8: [13.3, 150],
};

function parseEnvFile(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

function roleUrl(db: string, user: string, password: string): string {
  const u = new URL(DB_URL);
  u.pathname = `/${db}`;
  u.username = user;
  u.password = password;
  return u.toString();
}

function roleConn(db: string, user: string, password: string): pg.Pool {
  const pool = new pg.Pool({ connectionString: roleUrl(db, user, password), max: 1 });
  pool.on('error', () => {});
  return pool;
}

const num = (value: unknown): number => Number(value);

const codeOf = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
  } catch (err) {
    return (err as { code?: string })?.code ?? 'UNCLASSIFIED';
  }
  return 'accepted';
};

interface SandboxExecutors {
  withSandbox: (
    role: 'query' | 'raw',
    sandbox: string,
    op: (c: pg.Client) => Promise<unknown>,
  ) => Promise<unknown>;
  query: (sandbox: string) => {
    query: (sql: string, params?: unknown[]) => Promise<pg.QueryResult>;
  };
  raw: (sandbox: string, sql: string, params?: unknown[]) => Promise<pg.QueryResult>;
  rawBytes: (sandbox: string) => Promise<{
    plaintext: Array<Record<string, unknown>>;
    encrypted: Array<Record<string, unknown>>;
  }>;
  reset: (sandbox: string) => Promise<pg.QueryResult>;
  provision: (sandbox: string) => Promise<void>;
  snapshot: () => Promise<unknown>;
}

interface Plane {
  admin: pg.Pool;
  naivePool: pg.Pool;
  executors: SandboxExecutors;
  pools: { query: pg.Pool; raw: pg.Pool; control: pg.Pool };
  events: unknown[];
  db: string;
  tempDir: string;
}
// The playground links to root dist/; wait for stable output to avoid importing a partial build.

async function waitDistReady(budgetMs = 120_000): Promise<void> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const stableFor = 400;
    const start = Date.now();
    let present = distEntryPoints.every((p) => existsSync(p));
    while (present && Date.now() - start < stableFor) {
      await new Promise<void>((res) => setTimeout(res, 100));
      present = distEntryPoints.every((p) => existsSync(p));
    }
    if (present) return;
    if (Date.now() > deadline) {
      throw new Error('root dist/ did not become stable before the setup-db spawn');
    }
  }
}

async function runSetupDb(envFile: string, db: string): Promise<void> {
  const baseEnv = {
    ...process.env,
    DATABASE_URL: DB_URL.replace(/\/[^/]*$/, `/${db}`),
    AGENTS_MASTER_KEY: MASTER_KEY,
    PLAYGROUND_ENV_FILE: envFile,
    PLAYGROUND_ADMIN_DATABASE_URL: DB_URL.replace(/\/[^/]*$/, `/${db}`),
  };
  for (let attempt = 0; ; attempt += 1) {
    const result = spawnSync(process.execPath, [join(playgroundRoot, 'scripts', 'setup-db.mjs')], {
      cwd: playgroundRoot,
      env: baseEnv,
      encoding: 'utf8',
      timeout: 120_000,
    });
    if (result.status === 0) return;
    const output = `${result.stderr ?? ''}${result.stdout ?? ''}`;
    const distRace = output.includes('ERR_MODULE_NOT_FOUND') && output.includes('/dist/');
    if (!distRace || attempt >= 3) {
      throw new Error(
        `setup-db failed (attempt ${attempt + 1}): ${result.stderr ?? ''}\n${result.stdout ?? ''}`,
      );
    }
    rmSync(envFile, { force: true });
    await waitDistReady();
  }
}

describeFn('shared sandbox data plane (live Postgres required)', () => {
  let plane: Plane;

  const snapshot = async (): Promise<Snapshot> => (await plane.executors.snapshot()) as Snapshot;

  beforeAll(async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'sandbox-plane-'));
    const db = `sandbox_plane_${process.pid}_${Date.now() % 1_000_000}`;
    const adminMaster = new pg.Pool({ connectionString: DB_URL, max: 1 });
    await adminMaster.query(`CREATE DATABASE ${db}`);
    await adminMaster.end();

    const envFile = join(tempDir, '.env');
    await runSetupDb(envFile, db);

    const creds = parseEnvFile(envFile);
    const pools = {
      query: roleConn(
        db,
        'agents_playground_sandbox_query',
        creds['PLAYGROUND_SANDBOX_QUERY_DB_PASSWORD'],
      ),
      raw: roleConn(
        db,
        'agents_playground_sandbox_raw',
        creds['PLAYGROUND_SANDBOX_RAW_DB_PASSWORD'],
      ),
      control: roleConn(
        db,
        'agents_playground_sandbox_control',
        creds['PLAYGROUND_SANDBOX_CONTROL_DB_PASSWORD'],
      ),
    };
    const events: object[] = [];
    const executors = createSandboxExecutors({
      queryPool: pools.query,
      rawPool: pools.raw,
      controlPool: pools.control,
      events,
    });
    const naivePool = roleConn(
      db,
      'agents_playground_naive',
      creds['PLAYGROUND_NAIVE_DB_PASSWORD'],
    );
    const admin = new pg.Pool({ connectionString: DB_URL.replace(/\/[^/]*$/, `/${db}`), max: 2 });

    await executors.provision(SANDBOX_A);
    await executors.provision(SANDBOX_B);

    plane = { admin, naivePool, executors, pools, events, db, tempDir };
  }, 180_000);

  afterAll(async () => {
    if (!plane) return;
    const { admin, pools, naivePool, db, tempDir } = plane;
    for (const p of [...Object.values(pools), naivePool, admin]) {
      await p.end().catch(() => undefined);
    }
    // Connect to the maintenance database: an open connection to the test database would block DROP.
    const maintenance = new pg.Pool({ connectionString: DB_URL, max: 1 });
    try {
      await maintenance.query(
        'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ANY($1) AND pid <> pg_backend_pid()',
        [[db, `${db}_shared`]],
      );
      if (!/^[a-z0-9_]+$/.test(db)) throw new Error(`unsafe database identifier: ${db}`);
      await maintenance.query(`DROP DATABASE IF EXISTS "${db}_shared" WITH (FORCE)`);
      await maintenance.query(`DROP DATABASE IF EXISTS "${db}"`);
    } finally {
      await maintenance.end();
    }
    rmSync(tempDir, { recursive: true, force: true });
  }, 60_000);

  it('provides identical protected fixture and per-sandbox mutable rows', async () => {
    const e = plane.executors;
    const fixtureSql = 'SELECT id, instrument, price, counterparty FROM orders ORDER BY id';
    const fa = await e.query(SANDBOX_A).query(fixtureSql);
    const fb = await e.query(SANDBOX_B).query(fixtureSql);
    const toHex = (rows: Array<Record<string, unknown>>) =>
      rows.map((r) => ({
        ...r,
        price: (r.price as Buffer).toString('hex'),
        counterparty: (r.counterparty as Buffer).toString('hex'),
      }));
    expect(toHex(fa.rows)).toEqual(toHex(fb.rows));
    expect(fa.rows.map((r) => num(r.id))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(
      fa.rows.every((r) => r.price instanceof Buffer && r.counterparty instanceof Buffer),
    ).toBe(true);

    const plainSql = 'SELECT sandbox_id, id, instrument FROM orders_plaintext ORDER BY id';
    const ra = await e.raw(SANDBOX_A, plainSql);
    const rb = await e.raw(SANDBOX_B, plainSql);
    expect(ra.rows.map((r) => num(r.id))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(ra.rows.every((r) => r.sandbox_id === SANDBOX_A)).toBe(true);
    expect(rb.rows.every((r) => r.sandbox_id === SANDBOX_B)).toBe(true);
    expect(ra.rows.map((r) => [num(r.id), r.instrument])).toEqual(
      rb.rows.map((r) => [num(r.id), r.instrument]),
    );

    const cross = await e.raw(
      SANDBOX_A,
      `SELECT id FROM orders_plaintext WHERE sandbox_id = '${SANDBOX_B}'`,
    );
    expect(cross.rowCount).toBe(0);

    const ba = await e.rawBytes(SANDBOX_A);
    const bb = await e.rawBytes(SANDBOX_B);
    expect(ba.plaintext.map((r) => num(r.id))).toEqual(rb.rows.map((r) => num(r.id)));
    expect(ba.encrypted.map((r) => [r.price, r.counterparty])).toEqual(
      bb.encrypted.map((r) => [r.price, r.counterparty]),
    );
    expect(
      ba.encrypted.every((r) => typeof r.price === 'string' && r.price.startsWith('\\x')),
    ).toBe(true);
  }, 60_000);

  it('confines the hostile SQL matrix to the caller sandbox', async () => {
    const e = plane.executors;
    const forbidden: Array<[string, string]> = [
      ['private registry', 'SELECT * FROM sandbox_private.sandboxes'],
      ['private signing key', 'SELECT * FROM sandbox_private.context_secret'],
      ['private delete observer', 'SELECT * FROM sandbox_private.delete_events'],
      ['shared truncate', 'TRUNCATE orders_plaintext'],
      ['role catalog', 'SELECT * FROM pg_catalog.pg_authid'],
      [
        'context signer',
        `SELECT sandbox_private.issue_context('${SANDBOX_A}', pg_backend_pid(), txid_current()::text, current_user::text)`,
      ],
      ['reset other', `SELECT sandbox_private.reset_sandbox('${SANDBOX_B}')`],
      ['private snapshot', 'SELECT sandbox_private.snapshot()'],
      ['test oracle', `SELECT sandbox_private.probe_with_check('${SANDBOX_A}','${SANDBOX_B}')`],
      ['role escalation', 'SET ROLE agents_playground_sandbox_control'],
      ['session escalation', 'SET SESSION AUTHORIZATION agents_playground_sandbox_control'],
      ['subquery private', 'SELECT (SELECT sandbox_private.snapshot())'],
      [
        'reassign ownership',
        `UPDATE orders_plaintext SET sandbox_id = '${SANDBOX_B}' WHERE id = 1`,
      ],
      [
        'cross insert',
        `INSERT INTO orders_plaintext (sandbox_id,id,instrument,side,quantity,price,counterparty) VALUES ('${SANDBOX_B}',3,'forged','BUY',1,1,'forged')`,
      ],
      // Without the PUBLIC EXECUTE revocation a visitor could bypass the INSERT policy.
      ['probe insert', `SELECT sandbox_guard.probe_insert('${SANDBOX_A}', '${SANDBOX_B}')`],
    ];
    for (const role of ['query', 'raw'] as const) {
      for (const [name, sql] of forbidden) {
        expect(
          await codeOf(() => e.withSandbox(role, SANDBOX_A, (c) => c.query(sql))),
          `${role} / ${name}`,
        ).toBe('42501');
      }
    }
    // Exercise parser rejection separately from database privilege rejection.
    const sub = `SELECT stolen FROM (SELECT (SELECT counterparty FROM orders_plaintext WHERE sandbox_id = '${SANDBOX_B}' LIMIT 1) AS stolen) AS nested`;
    expect(await codeOf(() => e.raw(SANDBOX_A, sub))).toBe('SQL_POLICY_REJECTED');
    expect(
      await codeOf(() =>
        e.raw(SANDBOX_A, `UPDATE orders_plaintext SET sandbox_id = '${SANDBOX_B}' WHERE id = 1`),
      ),
    ).toBe('SQL_POLICY_REJECTED');
    expect(await codeOf(() => e.query(SANDBOX_A).query('SELECT 1; COMMIT; SELECT 2'))).toBe(
      'SQL_POLICY_REJECTED',
    );
  }, 60_000);

  it('serves two visitors over one pooled connection without leaking context', async () => {
    const e = plane.executors;
    await e.raw(SANDBOX_A, "UPDATE orders_plaintext SET status = 'A-MUTATED' WHERE id = 1");
    const b = await e.raw(SANDBOX_B, 'SELECT id, status FROM orders_plaintext WHERE id = 1');
    expect(b.rows).toHaveLength(1);
    expect(b.rows[0].status).toBe('OPEN');
    interface Event {
      role: string;
      pid: number;
      initialContextEmpty: boolean;
      cleanupContextEmpty: boolean;
    }
    const rawEvents = plane.events.filter((v) => (v as Event).role === 'raw') as Event[];
    const pids = [...new Set(rawEvents.map((ev) => ev.pid))];
    expect(pids.length).toBe(1);
    expect(rawEvents.every((ev) => ev.initialContextEmpty && ev.cleanupContextEmpty)).toBe(true);
    const client = await plane.pools.raw.connect();
    try {
      const { rows } = await client.query(`SELECT current_setting('sandbox.token', true) AS token`);
      expect(rows[0].token).toBeFalsy();
    } finally {
      client.release();
    }
    // Restore A's row so later assertions see a clean seed.
    await e.reset(SANDBOX_A);
  }, 60_000);

  it('resets one sandbox without touching the other or the fixture', async () => {
    const e = plane.executors;
    const fixtureBefore = await snapshot();
    const bBefore = fixtureBefore.privateRows.filter((r) => r.sandbox_id === SANDBOX_B);
    await e.raw(SANDBOX_A, 'UPDATE orders_plaintext SET price = 999, quantity = 1 WHERE id = 2');
    await e.raw(SANDBOX_A, 'DELETE FROM orders_plaintext WHERE id = 5');
    const mutated = await snapshot();
    const aMutated = mutated.privateRows.filter((r) => r.sandbox_id === SANDBOX_A);
    expect(aMutated.map((r) => r.id)).toEqual([1, 2, 3, 4, 6, 7, 8]);

    const deletesBefore = mutated.deleteEvents.length;
    await e.reset(SANDBOX_A);
    const after = await snapshot();

    const aAfter = after.privateRows
      .filter((r) => r.sandbox_id === SANDBOX_A)
      .sort((x, y) => x.id - y.id)
      .map((r) => [r.id, num(r.price), num(r.quantity)]);
    expect(aAfter).toEqual(
      Object.entries(SEED)
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([id, [price, qty]]) => [Number(id), price, qty]),
    );
    expect(after.privateRows.filter((r) => r.sandbox_id === SANDBOX_B)).toEqual(bBefore);
    expect(after.fixtureFingerprint).toBe(fixtureBefore.fixtureFingerprint);
    const newDeletes = after.deleteEvents.slice(deletesBefore);
    expect(newDeletes.length).toBe(7);
    expect(newDeletes.every((d) => d.sandbox_id === SANDBOX_A)).toBe(true);
  }, 60_000);

  it('keeps the legacy clone path and the shared plane mutually unreachable', async () => {
    const e = plane.executors;
    const legacy = await plane.naivePool.query(
      'SELECT id, instrument FROM public.orders_plaintext ORDER BY id LIMIT 3',
    );
    expect(legacy.rows.map((r) => num(r.id))).toEqual([1, 2, 3]);

    expect(
      await codeOf(() => plane.naivePool.query('SELECT * FROM sandbox.orders_plaintext')),
    ).toBe('42501');
    expect(
      await codeOf(() =>
        e.withSandbox('raw', SANDBOX_A, (c) => c.query('SELECT * FROM public.orders_plaintext')),
      ),
    ).toBe('42501');
    const legacyEnc = await plane.admin.query(
      'SELECT count(*)::int AS n FROM public.orders WHERE price IS NOT NULL',
    );
    const sharedEnc = await e.query(SANDBOX_A).query('SELECT count(*) AS n FROM orders');
    expect(legacyEnc.rows[0].n).toBe(8);
    expect(num(sharedEnc.rows[0].n)).toBe(8);
  }, 60_000);
});
