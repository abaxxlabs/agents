/**
 * Agents++ consumer smoke flow.
 *
 * The flow models two internal agents with different data views:
 * - `risk-full-access` can see every column in the order table.
 * - `desk-limited-agent` can see only desk, symbol, and notional.
 *
 * The test verifies the product promise at the integration boundary: scoped
 * credentials change what each agent can query, and an overscope attempt is
 * rejected before data leaves Postgres.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { AgentScope } from '@abaxxtech/agents/sql';
import {
  asMasterKey,
  ScopeViolationError,
  type MasterKey,
} from '@abaxxtech/agents';
import {
  DEFAULT_DATABASE_URL,
  ENCRYPTED_COLUMNS,
  TEST_TABLE,
  createSetupPool,
  ensureInfrastructure,
  registerEncryptedColumns,
  resetSmokeDatabase,
  resetSmokeDomain,
  seedOrders,
} from './schema.js';

export interface SmokeRunOptions {
  databaseUrl?: string;
  verbose?: boolean;
}

export interface SmokeRunResult {
  databaseUrl: string;
  fullAccessRows: Array<Record<string, unknown>>;
  limitedRows: Array<Record<string, unknown>>;
  overscopeBlocked: boolean;
  auditRecordCount: number;
  encryptedColumns: string[];
}

function redactDatabaseUrl(databaseUrl: string): string {
  return databaseUrl.replace(/\/\/.*@/, '//***@');
}

async function prepareDatabase(databaseUrl: string, masterKey: MasterKey): Promise<void> {
  const pool = createSetupPool(databaseUrl);
  try {
    await resetSmokeDatabase(pool);
    await ensureInfrastructure(pool);
    await resetSmokeDomain(pool);
    const columnKeys = await registerEncryptedColumns(pool, masterKey);
    await seedOrders(pool, columnKeys);
  } finally {
    await pool.end();
  }
}

export async function runSmoke(options: SmokeRunOptions = {}): Promise<SmokeRunResult> {
  // This is a local test app that intentionally uses mock human auth. The
  // library also checks NODE_ENV at auth time, so set a safe local default for
  // `npm run smoke`; Vitest already sets NODE_ENV=test for `npm test`.
  process.env.NODE_ENV ??= 'development';

  const databaseUrl = options.databaseUrl ?? process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;
  const masterKey = asMasterKey(randomBytes(32));
  await prepareDatabase(databaseUrl, masterKey);

  const scope = await AgentScope.create(
    {
      database: { connectionString: databaseUrl, poolSize: 3 },
      encryption: { columns: ENCRYPTED_COLUMNS },
      audit: { enabled: true, failOpen: false },
      devMode: true,
      scopeMode: 'projection',
    },
    { masterKey },
  );

  try {
    const session = await scope.authenticate({ mockHumanDid: 'Agents++ Smoke Tester' });
    const fullAgent = await scope.createAgent({
      name: 'risk-full-access',
      ownerDid: session.humanDid,
    });
    const limitedAgent = await scope.createAgent({
      name: 'desk-limited-agent',
      ownerDid: session.humanDid,
    });

    const fullCredential = await session.issueCredential({
      agent: fullAgent.did,
      columns: [
        `${TEST_TABLE}.desk`,
        `${TEST_TABLE}.symbol`,
        `${TEST_TABLE}.notional`,
        `${TEST_TABLE}.counterparty`,
        `${TEST_TABLE}.strategy`,
      ],
      actions: ['read'],
      expiresIn: '15m',
    });

    const limitedCredential = await session.issueCredential({
      agent: limitedAgent.did,
      columns: [
        `${TEST_TABLE}.desk`,
        `${TEST_TABLE}.symbol`,
        `${TEST_TABLE}.notional`,
      ],
      actions: ['read'],
      expiresIn: '15m',
    });

    const fullAccess = await scope.query({
      agent: fullAgent.did,
      credential: fullCredential,
      table: TEST_TABLE,
      sql: `SELECT desk, symbol, notional, counterparty, strategy FROM ${TEST_TABLE} ORDER BY symbol`,
    });

    const limited = await scope.query({
      agent: limitedAgent.did,
      credential: limitedCredential,
      table: TEST_TABLE,
      sql: `SELECT desk, symbol, notional FROM ${TEST_TABLE} ORDER BY symbol`,
    });

    let overscopeBlocked = false;
    try {
      await scope.query({
        agent: limitedAgent.did,
        credential: limitedCredential,
        table: TEST_TABLE,
        sql: `SELECT desk, symbol, notional, counterparty FROM ${TEST_TABLE} ORDER BY symbol`,
      });
    } catch (err) {
      if (err instanceof ScopeViolationError || (err as Error).name === 'ScopeViolationError') {
        overscopeBlocked = true;
      } else {
        throw err;
      }
    }

    assert.equal(overscopeBlocked, true, 'limited agent overscope query must be blocked');
    assert.equal(fullAccess.rows[0].counterparty, 'ALPHA-CAP');
    assert.deepEqual(Object.keys(limited.rows[0]).sort(), ['desk', 'notional', 'symbol']);

    const status = await scope.getServerStatus();
    const result: SmokeRunResult = {
      databaseUrl: redactDatabaseUrl(databaseUrl),
      fullAccessRows: fullAccess.rows,
      limitedRows: limited.rows,
      overscopeBlocked,
      auditRecordCount: status.auditRecordCount,
      encryptedColumns: status.encryptedColumns.sort(),
    };

    if (options.verbose ?? true) {
      console.log(JSON.stringify(result, null, 2));
    }

    return result;
  } finally {
    await scope.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runSmoke().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
