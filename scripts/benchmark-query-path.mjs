#!/usr/bin/env node
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
 * Repeatable benchmark for the QueryService -> ScopeEngine path.
 * Uses a synthetic in-process pg.Pool; measures credential verification,
 * SQL parsing, row shaping, column decryption, and audit signing.
 * Run via `npm run benchmark:query` after a fresh build.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, platform, release, totalmem } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMA_VERSION = 'abxagnts.query-path-benchmark.v1';
const BENCHMARK_NAME = 'query-service-scope-engine';

const DEFAULTS = Object.freeze({
  rows: 5_000,
  iterations: 200,
  warmup: 20,
  concurrency: 1,
  maxRows: 250,
});

const OUTPUT_SCHEMA = Object.freeze({
  schemaVersion: SCHEMA_VERSION,
  requiredTopLevelKeys: [
    'schemaVersion',
    'generatedAt',
    'benchmark',
    'environment',
    'config',
    'dataset',
    'patterns',
    'summary',
  ],
  patternMeasurementKeys: [
    'iterations',
    'warmupIterations',
    'concurrency',
    'totalMs',
    'throughputQps',
    'rowsPerQuery',
    'rowsPerSecond',
    'latencyMs',
  ],
  latencyKeys: ['min', 'mean', 'p50', 'p90', 'p95', 'p99', 'max'],
});

function usage() {
  return [
    'Usage: node scripts/benchmark-query-path.mjs [options]',
    '',
    'Options:',
    `  --rows <n>          Synthetic order_book row count (default ${DEFAULTS.rows})`,
    `  --iterations <n>    Measured iterations per pattern (default ${DEFAULTS.iterations})`,
    `  --warmup <n>        Warmup iterations per pattern (default ${DEFAULTS.warmup})`,
    `  --concurrency <n>   In-flight queries per pattern (default ${DEFAULTS.concurrency})`,
    `  --max-rows <n>      QueryService row cap (default ${DEFAULTS.maxRows})`,
    '  --json              Print the full benchmark report as JSON',
    '  --output <path>     Write the full benchmark report JSON to a file',
    '  --schema            Print the benchmark output schema contract',
    '  --contract          Print a deterministic sample report for contract tests',
    '  --help              Show this help',
  ].join('\n');
}

function parseArgs(argv) {
  const args = {
    ...DEFAULTS,
    json: false,
    output: undefined,
    schema: false,
    contract: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const [flag, inlineValue] = arg.split('=', 2);
    const readValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${flag}`);
      return argv[i];
    };

    switch (flag) {
      case '--rows':
        args.rows = parsePositiveInteger(readValue(), flag);
        break;
      case '--iterations':
        args.iterations = parsePositiveInteger(readValue(), flag);
        break;
      case '--warmup':
        args.warmup = parseNonNegativeInteger(readValue(), flag);
        break;
      case '--concurrency':
        args.concurrency = parsePositiveInteger(readValue(), flag);
        break;
      case '--max-rows':
        args.maxRows = parsePositiveInteger(readValue(), flag);
        break;
      case '--json':
        args.json = true;
        break;
      case '--output':
        args.output = resolve(ROOT, readValue());
        break;
      case '--schema':
        args.schema = true;
        break;
      case '--contract':
        args.contract = true;
        args.json = true;
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return args;
}

function parsePositiveInteger(value, flag) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return parsed;
}

function parseNonNegativeInteger(value, flag) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${flag} must be a non-negative integer`);
  }
  return parsed;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log(usage());
    return;
  }

  if (args.schema) {
    console.log(JSON.stringify(OUTPUT_SCHEMA, null, 2));
    return;
  }

  const report = args.contract
    ? createContractReport()
    : await runBenchmark(args);

  validateReportShape(report);

  if (args.output) {
    writeFileSync(args.output, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printHumanSummary(report);
  }
}

async function runBenchmark(args) {
  assertBuiltArtifacts();
  const runtime = await loadRuntime();
  const fixture = createFixture(runtime, args);
  const patterns = createPatterns(fixture, args);
  const measuredPatterns = [];

  for (const pattern of patterns) {
    const measurement = await measurePattern(fixture.service, pattern, args);
    measuredPatterns.push({
      name: pattern.name,
      description: pattern.description,
      table: pattern.input.table,
      sql: pattern.input.sql,
      params: pattern.input.params,
      selectedColumns: pattern.selectedColumns,
      referencedColumns: pattern.referencedColumns,
      expectedReturnedRows: pattern.expectedReturnedRows,
      measurement,
    });
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    benchmark: {
      name: BENCHMARK_NAME,
      packageName: readPackageJson().name,
      packageVersion: readPackageJson().version,
      git: gitContext(),
    },
    environment: environmentContext(),
    config: {
      rows: args.rows,
      iterations: args.iterations,
      warmupIterations: args.warmup,
      concurrency: args.concurrency,
      maxRows: args.maxRows,
      scopeMode: 'projection',
      queryPath: 'createQueryService -> ScopeEngine.query',
      database: 'synthetic in-process pg.Pool fixture',
      audit: 'AuditLogger enabled with in-memory AuditStore',
      sqlParser: 'libpg-query',
      credentialMode: 'raw VC input; ScopeEngine wraps a fresh VP per query',
    },
    dataset: fixture.dataset,
    patterns: measuredPatterns,
    summary: summarize(measuredPatterns),
  };
}

function assertBuiltArtifacts() {
  const required = [
    'dist/services/index.js',
    'dist/sql/scope-engine.js',
    'dist/vc-verifier.js',
    'dist/encryption/column.js',
  ];
  const missing = required.filter((relativePath) => !existsSync(resolve(ROOT, relativePath)));
  if (missing.length > 0) {
    throw new Error(
      [
        'Benchmark requires fresh ESM build artifacts.',
        `Missing: ${missing.join(', ')}`,
        'Run: npm run build:esm',
      ].join('\n'),
    );
  }
}

async function loadRuntime() {
  const importDist = (relativePath) => import(pathToFileURL(resolve(ROOT, relativePath)).href);
  const [
    services,
    scopeEngine,
    verifier,
    revocation,
    audit,
    encryption,
    auth,
  ] = await Promise.all([
    importDist('dist/services/index.js'),
    importDist('dist/sql/scope-engine.js'),
    importDist('dist/vc-verifier.js'),
    importDist('dist/storage/memory/revocation-store.js'),
    importDist('dist/audit-logger.js'),
    importDist('dist/encryption/column.js'),
    importDist('dist/auth/index.js'),
  ]);

  return {
    createQueryService: services.createQueryService,
    ScopeEngine: scopeEngine.ScopeEngine,
    VcVerifier: verifier.VcVerifier,
    InMemoryRevocationStore: revocation.InMemoryRevocationStore,
    AuditLogger: audit.AuditLogger,
    encrypt: encryption.encrypt,
    generateColumnKey: encryption.generateColumnKey,
    generateDidKey: auth.generateDidKey,
    issueCredential: auth.issueCredential,
    createSigner: auth.createSigner,
  };
}

function createFixture(runtime, args) {
  const human = runtime.generateDidKey();
  const agent = runtime.generateDidKey();
  const server = runtime.generateDidKey();

  const verifier = new runtime.VcVerifier({
    clockSkew: '30s',
    revocationStore: new runtime.InMemoryRevocationStore(),
  });
  verifier.registerKey(human.did, human.publicKey);
  verifier.registerKey(agent.did, agent.publicKey);
  verifier.registerKey(server.did, server.publicKey);

  const columnKeys = new Map([
    ['order_book.account_id', runtime.generateColumnKey()],
    ['order_book.counterparty', runtime.generateColumnKey()],
    ['order_book.trader_note', runtime.generateColumnKey()],
  ]);
  const encryptedColumns = new Set(columnKeys.keys());
  const rows = createRows(args.rows, runtime.encrypt, columnKeys);
  const pool = createSyntheticPool(rows);
  const auditStore = createInMemoryAuditStore();

  const registeredAgent = {
    did: agent.did,
    name: 'Benchmark Query Agent',
    ownerDid: human.did,
    signer: runtime.createSigner(agent.privateKey),
    publicKey: agent.publicKey,
  };
  const agents = new Map([[agent.did, registeredAgent]]);

  const engine = new runtime.ScopeEngine({
    pool,
    verifier,
    auditLogger: new runtime.AuditLogger({
      auditStore,
      enabled: true,
      failOpen: false,
    }),
    columnKeys,
    encryptedColumns,
    agents,
    verifierDid: server.did,
    scopeMode: 'projection',
    agentStore: {
      findByDid: async (did) => {
        const found = agents.get(did);
        return found
          ? { did: found.did, name: found.name, ownerDid: found.ownerDid, createdAt: new Date(0) }
          : null;
      },
      create: async () => undefined,
      list: async () => [],
      listAll: async () => [],
      count: async () => agents.size,
    },
  });

  const columns = datasetColumns();
  const credential = runtime.issueCredential(human.did, human.privateKey, {
    agent: agent.did,
    columns: columns.map((column) => `order_book.${column.name}`),
    actions: ['read'],
    expiresIn: '4h',
  });

  return {
    service: runtime.createQueryService({ executor: engine, maxRows: args.maxRows }),
    agentDid: agent.did,
    credential,
    dataset: {
      table: 'order_book',
      rowCount: args.rows,
      rowShape:
        'Capital-markets order book rows with public execution fields and three encrypted sensitive fields.',
      columns,
      encryptedColumns: Array.from(encryptedColumns),
    },
  };
}

function createRows(rowCount, encrypt, columnKeys) {
  const instruments = ['LNG-MAY26', 'LNG-JUN26', 'GOLD-MAY26', 'CARBON-DEC26', 'NICKEL-JUL26'];
  const venues = ['AEX', 'SGX', 'ICE'];
  const counterparties = ['CP-NORTH', 'CP-SOUTH', 'CP-EAST', 'CP-WEST'];
  const accountKey = columnKeys.get('order_book.account_id');
  const counterpartyKey = columnKeys.get('order_book.counterparty');
  const noteKey = columnKeys.get('order_book.trader_note');

  return Array.from({ length: rowCount }, (_, index) => {
    const instrument = instruments[index % instruments.length];
    const side = index % 2 === 0 ? 'BUY' : 'SELL';
    const venue = venues[index % venues.length];
    return {
      order_id: index + 1,
      instrument,
      side,
      price: Number((72 + (index % 750) / 10).toFixed(2)),
      quantity: 10 + (index % 90),
      venue,
      updated_at: `2026-04-29T${String(index % 24).padStart(2, '0')}:00:00.000Z`,
      account_id: encrypt(`ACC-${String(index % 1_000).padStart(4, '0')}`, accountKey),
      counterparty: encrypt(counterparties[index % counterparties.length], counterpartyKey),
      trader_note: encrypt(`risk-bucket-${index % 12}`, noteKey),
    };
  });
}

function createSyntheticPool(rows) {
  return {
    query: async (sql, params = []) => {
      let resultRows = rows;
      if (sql.includes('instrument = $1')) {
        resultRows = resultRows.filter((row) => row.instrument === params[0]);
      } else if (sql.includes('venue = $1')) {
        resultRows = resultRows.filter((row) => row.venue === params[0]);
      } else if (sql.includes('side = $1')) {
        resultRows = resultRows.filter((row) => row.side === params[0]);
      }

      const limit = parseLimit(sql);
      if (limit !== undefined) resultRows = resultRows.slice(0, limit);

      const selectedColumns = parseSelectedColumns(sql);
      const projected = resultRows.map((row) => {
        const out = {};
        for (const column of selectedColumns) out[column] = row[column];
        return out;
      });
      return { rows: projected, rowCount: projected.length };
    },
  };
}

function parseLimit(sql) {
  const match = sql.match(/\blimit\s+(\d+)/i);
  return match ? Number.parseInt(match[1], 10) : undefined;
}

function parseSelectedColumns(sql) {
  const match = sql.match(/^\s*select\s+(.+?)\s+from\s+/is);
  if (!match) throw new Error(`Benchmark SQL is not a simple SELECT: ${sql}`);
  return match[1].split(',').map((raw) => raw.trim().replace(/\s+as\s+\w+$/i, ''));
}

function datasetColumns() {
  return [
    { name: 'order_id', type: 'integer', encrypted: false },
    { name: 'instrument', type: 'text', encrypted: false },
    { name: 'side', type: 'text', encrypted: false },
    { name: 'price', type: 'numeric', encrypted: false },
    { name: 'quantity', type: 'integer', encrypted: false },
    { name: 'venue', type: 'text', encrypted: false },
    { name: 'updated_at', type: 'timestamp', encrypted: false },
    { name: 'account_id', type: 'text', encrypted: true },
    { name: 'counterparty', type: 'text', encrypted: true },
    { name: 'trader_note', type: 'text', encrypted: true },
  ];
}

function createPatterns(fixture, args) {
  const baseInput = {
    agent: fixture.agentDid,
    credential: fixture.credential,
    table: 'order_book',
    orgId: 'benchmark-org',
  };

  return [
    {
      name: 'public_projection_100_rows',
      description:
        'Narrow public projection with WHERE and LIMIT; exercises credential verification, parser checks, pool call, and audit.',
      input: {
        ...baseInput,
        sql:
          'SELECT order_id, instrument, side, price, quantity FROM order_book WHERE instrument = $1 LIMIT 100',
        params: ['LNG-MAY26'],
      },
      selectedColumns: ['order_id', 'instrument', 'side', 'price', 'quantity'],
      referencedColumns: ['order_id', 'instrument', 'side', 'price', 'quantity'],
      expectedReturnedRows: Math.min(args.maxRows, 100, Math.ceil(args.rows / 5)),
    },
    {
      name: 'encrypted_projection_100_rows',
      description:
        'Sensitive projection decrypting three encrypted columns per row after the projection boundary passes.',
      input: {
        ...baseInput,
        sql:
          'SELECT order_id, instrument, account_id, counterparty, trader_note FROM order_book WHERE venue = $1 LIMIT 100',
        params: ['SGX'],
      },
      selectedColumns: ['order_id', 'instrument', 'account_id', 'counterparty', 'trader_note'],
      referencedColumns: ['order_id', 'instrument', 'account_id', 'counterparty', 'trader_note', 'venue'],
      expectedReturnedRows: Math.min(args.maxRows, 100, Math.floor((args.rows + 1) / 3)),
    },
    {
      name: 'service_row_cap_1000_to_max_rows',
      description:
        'Wide query returning 1000 scoped rows from ScopeEngine, then applying QueryService maxRows response shaping.',
      input: {
        ...baseInput,
        sql:
          'SELECT order_id, instrument, side, price, quantity, venue, updated_at, account_id, counterparty, trader_note FROM order_book WHERE side = $1 LIMIT 1000',
        params: ['BUY'],
      },
      selectedColumns: [
        'order_id',
        'instrument',
        'side',
        'price',
        'quantity',
        'venue',
        'updated_at',
        'account_id',
        'counterparty',
        'trader_note',
      ],
      referencedColumns: [
        'order_id',
        'instrument',
        'side',
        'price',
        'quantity',
        'venue',
        'updated_at',
        'account_id',
        'counterparty',
        'trader_note',
      ],
      expectedReturnedRows: Math.min(args.maxRows, 1_000, Math.ceil(args.rows / 2)),
    },
  ];
}

async function measurePattern(service, pattern, args) {
  for (let i = 0; i < args.warmup; i += 1) {
    await runOne(service, pattern);
  }

  const latencies = [];
  const totalStart = performance.now();
  let remaining = args.iterations;

  while (remaining > 0) {
    const batchSize = Math.min(args.concurrency, remaining);
    const batch = Array.from({ length: batchSize }, async () => {
      const start = performance.now();
      await runOne(service, pattern);
      latencies.push(performance.now() - start);
    });
    await Promise.all(batch);
    remaining -= batchSize;
  }

  const totalMs = performance.now() - totalStart;
  const stats = latencyStats(latencies);
  const rowsPerQuery = pattern.expectedReturnedRows;

  return {
    iterations: args.iterations,
    warmupIterations: args.warmup,
    concurrency: args.concurrency,
    totalMs: round(totalMs),
    throughputQps: round(args.iterations / (totalMs / 1_000)),
    rowsPerQuery,
    rowsPerSecond: round((args.iterations * rowsPerQuery) / (totalMs / 1_000)),
    latencyMs: stats,
  };
}

async function runOne(service, pattern) {
  const result = await service.execute(pattern.input);
  if (result.rows.length !== pattern.expectedReturnedRows) {
    throw new Error(
      `${pattern.name} returned ${result.rows.length} rows; expected ${pattern.expectedReturnedRows}`,
    );
  }
  return result;
}

function latencyStats(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  return {
    min: round(sorted[0]),
    mean: round(sum / sorted.length),
    p50: percentile(sorted, 50),
    p90: percentile(sorted, 90),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    max: round(sorted[sorted.length - 1]),
  };
}

function percentile(sorted, p) {
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return round(sorted[index]);
}

function summarize(patterns) {
  const byP95 = [...patterns].sort((a, b) => a.measurement.latencyMs.p95 - b.measurement.latencyMs.p95);
  const encrypted = patterns.find((pattern) => pattern.name === 'encrypted_projection_100_rows');
  const publicOnly = patterns.find((pattern) => pattern.name === 'public_projection_100_rows');
  const rowCap = patterns.find((pattern) => pattern.name === 'service_row_cap_1000_to_max_rows');
  const bottlenecks = [
    'Every query performs credential verification, libpg-query parsing/projection checks, and audit signing.',
    'AuditLogger serializes audit-chain updates; concurrent runs measure that lock as part of the query path.',
  ];

  if (encrypted && publicOnly) {
    const ratio = encrypted.measurement.latencyMs.p95 / publicOnly.measurement.latencyMs.p95;
    bottlenecks.push(`Encrypted projection p95 was ${round(ratio)}x the public projection p95 in this run.`);
  }
  if (rowCap) {
    bottlenecks.push(
      `Row cap is applied after ScopeEngine processing; the wide pattern still decrypts up to 1000 rows before returning ${rowCap.measurement.rowsPerQuery}.`,
    );
  }

  return {
    fastestPatternByP95: byP95[0]?.name,
    slowestPatternByP95: byP95[byP95.length - 1]?.name,
    bottlenecks,
  };
}

function createInMemoryAuditStore() {
  const records = [];
  return {
    append: async (record) => {
      records.push(record);
    },
    loadLastRecord: async () => records.at(-1) ?? null,
    loadLastRecordLocked: async () => records.at(-1) ?? null,
    query: async () => [...records],
  };
}

function readPackageJson() {
  return JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf8'));
}

function gitContext() {
  return {
    branch: git(['branch', '--show-current']),
    commit: git(['rev-parse', '--short', 'HEAD']),
    dirty: git(['status', '--short']).length > 0,
  };
}

function git(args) {
  const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'unknown';
}

function environmentContext() {
  const cpuList = cpus();
  return {
    node: process.version,
    platform: `${platform()} ${release()}`,
    arch: process.arch,
    cpuModel: cpuList[0]?.model ?? 'unknown',
    cpuCount: cpuList.length,
    totalMemoryMb: Math.round(totalmem() / 1024 / 1024),
  };
}

function createContractReport() {
  return {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: '2026-04-29T00:00:00.000Z',
    benchmark: {
      name: BENCHMARK_NAME,
      packageName: '@abaxxlabs/agents',
      packageVersion: '0.0.0-contract',
      git: { branch: 'contract', commit: '0000000', dirty: false },
    },
    environment: {
      node: 'v0.0.0',
      platform: 'contract',
      arch: 'contract',
      cpuModel: 'contract',
      cpuCount: 1,
      totalMemoryMb: 1,
    },
    config: {
      rows: 10,
      iterations: 1,
      warmupIterations: 0,
      concurrency: 1,
      maxRows: 5,
      scopeMode: 'projection',
      queryPath: 'createQueryService -> ScopeEngine.query',
      database: 'synthetic in-process pg.Pool fixture',
      audit: 'AuditLogger enabled with in-memory AuditStore',
      sqlParser: 'libpg-query',
      credentialMode: 'raw VC input; ScopeEngine wraps a fresh VP per query',
    },
    dataset: {
      table: 'order_book',
      rowCount: 10,
      rowShape: 'contract fixture',
      columns: datasetColumns(),
      encryptedColumns: ['order_book.account_id', 'order_book.counterparty', 'order_book.trader_note'],
    },
    patterns: [
      {
        name: 'contract_pattern',
        description: 'contract fixture',
        table: 'order_book',
        sql: 'SELECT order_id FROM order_book LIMIT 1',
        params: [],
        selectedColumns: ['order_id'],
        referencedColumns: ['order_id'],
        expectedReturnedRows: 1,
        measurement: {
          iterations: 1,
          warmupIterations: 0,
          concurrency: 1,
          totalMs: 1,
          throughputQps: 1,
          rowsPerQuery: 1,
          rowsPerSecond: 1,
          latencyMs: { min: 1, mean: 1, p50: 1, p90: 1, p95: 1, p99: 1, max: 1 },
        },
      },
    ],
    summary: {
      fastestPatternByP95: 'contract_pattern',
      slowestPatternByP95: 'contract_pattern',
      bottlenecks: ['contract fixture'],
    },
  };
}

function validateReportShape(report) {
  for (const key of OUTPUT_SCHEMA.requiredTopLevelKeys) {
    if (!(key in report)) throw new Error(`Benchmark report missing top-level key: ${key}`);
  }
  if (report.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`Benchmark report schemaVersion must be ${SCHEMA_VERSION}`);
  }
  if (!Array.isArray(report.patterns) || report.patterns.length === 0) {
    throw new Error('Benchmark report must include at least one pattern');
  }
  for (const pattern of report.patterns) {
    if (typeof pattern.name !== 'string') throw new Error('Benchmark pattern missing name');
    if (!pattern.measurement) throw new Error(`Benchmark pattern ${pattern.name} missing measurement`);
    for (const key of OUTPUT_SCHEMA.patternMeasurementKeys) {
      if (!(key in pattern.measurement)) {
        throw new Error(`Benchmark pattern ${pattern.name} missing measurement.${key}`);
      }
    }
    for (const key of OUTPUT_SCHEMA.latencyKeys) {
      if (!(key in pattern.measurement.latencyMs)) {
        throw new Error(`Benchmark pattern ${pattern.name} missing latencyMs.${key}`);
      }
    }
  }
}

function printHumanSummary(report) {
  console.log(`${report.benchmark.name} (${report.schemaVersion})`);
  console.log(`Generated: ${report.generatedAt}`);
  console.log(`Rows: ${report.config.rows}; iterations: ${report.config.iterations}; concurrency: ${report.config.concurrency}`);
  console.log('');
  for (const pattern of report.patterns) {
    const m = pattern.measurement;
    console.log(
      [
        pattern.name,
        `p50=${m.latencyMs.p50}ms`,
        `p95=${m.latencyMs.p95}ms`,
        `p99=${m.latencyMs.p99}ms`,
        `qps=${m.throughputQps}`,
        `rows/query=${m.rowsPerQuery}`,
      ].join('  '),
    );
  }
  console.log('');
  console.log(`Fastest p95: ${report.summary.fastestPatternByP95}`);
  console.log(`Slowest p95: ${report.summary.slowestPatternByP95}`);
  console.log('Use --json or --output <path> for the full machine-readable report.');
}

function round(value) {
  return Number(value.toFixed(3));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
