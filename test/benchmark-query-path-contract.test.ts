import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');

function runBenchmarkContract(): unknown {
  const result = spawnSync('node', ['scripts/benchmark-query-path.mjs', '--contract', '--json'], {
    cwd: ROOT,
    encoding: 'utf8',
  });

  if (result.status !== 0) {
    throw new Error(
      [
        'benchmark contract command failed',
        result.stdout,
        result.stderr,
      ].filter(Boolean).join('\n'),
    );
  }

  return JSON.parse(result.stdout) as unknown;
}

describe('query-path benchmark contract', () => {
  it('emits the stable report envelope', () => {
    const report = runBenchmarkContract() as {
      schemaVersion?: string;
      benchmark?: { name?: string };
      config?: { queryPath?: string; database?: string; scopeMode?: string };
      dataset?: { table?: string; rowCount?: number; encryptedColumns?: string[] };
      patterns?: Array<{
        name?: string;
        measurement?: {
          iterations?: number;
          throughputQps?: number;
          rowsPerQuery?: number;
          latencyMs?: Record<string, number>;
        };
      }>;
      summary?: { bottlenecks?: string[] };
    };

    expect(report.schemaVersion).toBe('abxagnts.query-path-benchmark.v1');
    expect(report.benchmark).toMatchObject({
      name: 'query-service-scope-engine',
    });
    expect(report.config).toMatchObject({
      queryPath: 'createQueryService -> ScopeEngine.query',
      database: 'synthetic in-process pg.Pool fixture',
      scopeMode: 'projection',
    });
    expect(report.dataset).toMatchObject({
      table: 'order_book',
      rowCount: 10,
    });
    expect(report.dataset?.encryptedColumns).toEqual([
      'order_book.account_id',
      'order_book.counterparty',
      'order_book.trader_note',
    ]);

    expect(report.patterns).toHaveLength(1);
    expect(report.patterns?.[0].measurement).toMatchObject({
      iterations: 1,
      throughputQps: 1,
      rowsPerQuery: 1,
    });
    expect(Object.keys(report.patterns?.[0].measurement?.latencyMs ?? {}).sort()).toEqual([
      'max',
      'mean',
      'min',
      'p50',
      'p90',
      'p95',
      'p99',
    ]);
    expect(report.summary?.bottlenecks).toEqual(['contract fixture']);
  });
});
