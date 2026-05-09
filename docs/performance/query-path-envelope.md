# Query Path Performance Envelope

ABXAGNTS-316 publishes a repeatable benchmark for the shared query path:
`createQueryService -> ScopeEngine.query`. The goal is release-readiness
evidence, not optimization. The benchmark documents the current latency,
throughput, and bottleneck profile for representative scoped-query behavior so
future changes can be compared against a known envelope.

This benchmark intentionally avoids ABXAGNTS-317 territory. It does not add
server route logging, operational telemetry, REST instrumentation, or mounted
MCP telemetry. It uses an in-process synthetic `pg.Pool` fixture so the measured
cost is the library path: credential verification, VP wrapping, `libpg-query`
read-only/projection checks, scoped row shaping, encrypted-column decryption,
and audit signing/append.

## How to Rerun

```bash
npm run benchmark:query
```

For machine-readable file output:

```bash
npm run benchmark:query -- --json --output docs/performance/query-path-envelope-baseline-YYYY-MM-DD.json
```

Use a new dated filename for each saved baseline so historical runs are not
overwritten.

For stdout piping, run npm in silent mode so npm's script banners do not prefix
the JSON:

```bash
npm run --silent benchmark:query -- --json
```

Useful knobs:

```bash
npm run benchmark:query -- --rows 10000 --iterations 500 --warmup 50 --concurrency 4 --max-rows 250 --json
```

The script builds fresh ESM artifacts first (`npm run build:esm`) because the
benchmark imports from `dist/`. The JSON schema is versioned as
`abxagnts.query-path-benchmark.v1`; `test/benchmark-query-path-contract.test.ts`
guards the report envelope without running the full benchmark in unit tests.

## Fixture

Dataset: synthetic `order_book` table with 5,000 rows by default.

Columns:

| Column | Type | Encrypted |
| --- | --- | --- |
| `order_id` | integer | no |
| `instrument` | text | no |
| `side` | text | no |
| `price` | numeric | no |
| `quantity` | integer | no |
| `venue` | text | no |
| `updated_at` | timestamp | no |
| `account_id` | text | yes |
| `counterparty` | text | yes |
| `trader_note` | text | yes |

Config:

| Setting | Value |
| --- | --- |
| Query path | `createQueryService -> ScopeEngine.query` |
| Scope mode | `projection` |
| SQL parser | `libpg-query` |
| Database | synthetic in-process `pg.Pool` fixture |
| Audit | `AuditLogger` enabled with in-memory `AuditStore` |
| Credential mode | raw VC input; ScopeEngine wraps a fresh VP per query |
| Default row cap | 250 returned rows |

## Query Patterns

| Pattern | Query Shape | Why It Exists |
| --- | --- | --- |
| `public_projection_100_rows` | narrow public projection, `WHERE instrument = $1`, `LIMIT 100` | Baseline scoped query with parser, credential, pool, row shaping, and audit cost but no decrypt work. |
| `encrypted_projection_100_rows` | five-column projection including `account_id`, `counterparty`, `trader_note`, `WHERE venue = $1`, `LIMIT 100` | Measures the added cost of decrypting three encrypted columns per row after the projection boundary passes. |
| `service_row_cap_1000_to_max_rows` | wide ten-column projection, `WHERE side = $1`, `LIMIT 1000`, service cap returns 250 | Shows that `maxRows` is response shaping after ScopeEngine processing; the path still processes/decrypts the wider scoped result. |

## Captured Baseline

Captured on 2026-04-29 from branch
`release-review-8-abxagnts-316-317` at commit `3f20d3a` with a dirty worktree
containing this benchmark work.

Environment:

| Field | Value |
| --- | --- |
| Node | `v25.8.0` |
| Platform | `darwin 24.6.0` |
| Architecture | `arm64` |
| CPU | Apple M4, 10 cores |
| Memory | 24,576 MB |

Benchmark config: 5,000 rows, 200 measured iterations per pattern, 20 warmup
iterations, concurrency 1, `maxRows` 250.

| Pattern | p50 ms | p95 ms | p99 ms | Throughput qps | Returned rows/query |
| --- | ---: | ---: | ---: | ---: | ---: |
| `public_projection_100_rows` | 0.362 | 0.639 | 1.007 | 2,434.284 | 100 |
| `encrypted_projection_100_rows` | 0.822 | 1.300 | 1.522 | 1,125.929 | 100 |
| `service_row_cap_1000_to_max_rows` | 6.040 | 8.291 | 10.287 | 154.574 | 250 |

Raw baseline: `docs/performance/query-path-envelope-baseline-2026-04-29.json`.

## Interpretation

The current envelope is sub-millisecond p95 for narrow public projections and
about 1.3 ms p95 for 100-row encrypted projections on the captured local
environment. The wide row-cap pattern is much slower because the service cap
does not reduce ScopeEngine work; ScopeEngine still receives and decrypts up to
1,000 scoped rows before `QueryService` slices the response to 250 rows.

Observed bottlenecks:

- Each query performs credential verification, fresh VP wrapping, SQL parsing,
  projection-boundary checks, and audit signing.
- Encrypted projections add AES-GCM decrypt work per encrypted cell; in the
  captured run, encrypted p95 was about 2.0x the public projection p95.
- Audit hash-chain updates are serialized by `AuditLogger`; concurrent runs
  should be interpreted as measuring that lock as part of the query path.
- The synthetic pool removes database network and storage variance. Use these
  numbers to compare library-path regressions, not to size production Postgres.

Regression guidance: compare p95 and throughput per pattern against the same
rows/iterations/concurrency config. A change that materially raises
`public_projection_100_rows` likely affects credential, parser, projection, or
audit overhead. A change isolated to encrypted or row-cap patterns likely
affects decrypt cost, row shaping, or service response slicing.
