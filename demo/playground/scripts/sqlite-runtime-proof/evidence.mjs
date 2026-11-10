const COMMON = ['separate-unprivileged-process-pools', 'postgres-query-role-read-only-data-and-key-metadata',
  'postgres-raw-role-plaintext-only', 'postgres-protected-columns-are-ciphertext'];
const CLEANUP = ['worker-runtime-cleanup', 'worker-query-pool-closed', 'worker-raw-pool-closed',
  'worker-master-buffer-overwritten', 'worker-no-idle-pool-errors'];
const REQUIRED = {
  run: [...COMMON, ...CLEANUP, 'independent-initial-empty-sqlite-stores', 'agent-registry-isolation',
    'A-encrypted-price-allowed-and-decrypted', 'B-encrypted-price-allowed-and-decrypted',
    'wrong-visitor-credential-denied-with-fresh-B-presentation', 'narrow-credential-denies-counterparty-same-sql',
    'broad-credential-positive-control-same-sql', 'real-credential-has-owner-signature-and-jti',
    'revoked-query-rejected-with-fresh-presentation', 'sqlite-revocation-isolation', 'audit-store-isolation',
    'A-full-audit-chain', 'B-full-audit-chain', 'A-audit-signatures-and-covered-fields', 'B-audit-signatures-and-covered-fields',
    'A-corrupt-signature-rejected', 'B-corrupt-signature-rejected', 'runtime-close-blocks-new-admission',
    'runtime-close-drains-accepted-query', 'A-state-unavailable-through-retained-storage-after-explicit-close',
    'caller-owned-A-buffers-overwritten', 'caller-owned-B-buffers-overwritten', 'SDK-stale-handle-behavior-characterized',
    'B-operates-after-A-storage-disposal', 'fixed-workload-measured-cycles', 'final-cycle-resource-invariants'],
  restart: [...COMMON, ...CLEANUP, 'restart-previous-public-agent-identities-supplied',
    'restart-empty-agents-audit-and-revocations', 'restart-old-agents-not-recovered',
    'restart-fresh-agent-queries-same-postgres', 'restart-B-survives-A-close', 'restart-no-live-runtimes'],
};

export function provenanceMatches(runtime, expected) {
  return /^v22\./.test(runtime?.node ?? '') && runtime.platform === 'linux'
    && Number.isInteger(runtime.uid) && runtime.uid > 0
    && runtime.sdk?.version === expected.sdkVersion
    && runtime.betterSqlite3?.version === expected.sqliteVersion && runtime.betterSqlite3.probe === 'PASS'
    && typeof runtime.betterSqlite3.sqliteVersion === 'string'
    && runtime.imagePackageLock?.sha256 === expected.lockSha256;
}

function accounted(summary, count) {
  return summary?.live === 0 && summary.inFlight === 0 && summary.created === count && summary.closed === count
    && summary.storesCreated === count && summary.storesClosed === count && summary.callerOwnedBuffersZeroed === true;
}

function measuredSample(sample) {
  return sample && ['rss', 'heapTotal', 'heapUsed', 'external', 'arrayBuffers'].every((key) =>
    Number.isFinite(sample.memoryUsage?.[key]) && sample.memoryUsage[key] >= 0)
    && sample.activeResources && Object.keys(sample.activeResources).length > 0
    && ['query', 'raw'].every((key) => Number.isInteger(sample.pools?.[key]?.total)
      && sample.pools[key].total >= 0 && sample.pools[key].total <= (key === 'query' ? 2 : 1)
      && sample.pools[key].waiting === 0);
}

export function evidenceFailures(result, expected) {
  const failures = [];
  if (!expected || !REQUIRED[expected.action]) return ['missing-expected-action'];
  if (result.protocolVersion !== 1 || result.action !== expected.action) failures.push('worker-protocol-or-action');
  if (!provenanceMatches(result.runtime, expected)) failures.push('image-runtime-provenance');
  const names = new Set(result.checks.filter((check) => check.status === 'PASS').map((check) => check.name));
  for (const name of REQUIRED[expected.action]) if (!names.has(name)) failures.push(`missing:${name}`);
  const configuration = result.metrics?.configuration;
  if (configuration?.cycles !== expected.cycles || configuration?.warmup !== expected.warmup) failures.push('requested-workload');
  const count = expected.action === 'run' ? 2 + expected.cycles + expected.warmup : 2;
  if (!accounted(result.metrics?.finalBeforePoolClose?.runtimes, count)) failures.push('runtime-resource-accounting');
  if (!['query', 'raw'].every((key) => result.metrics?.finalAfterPoolClose?.pools?.[key]?.total === 0
    && result.metrics.finalAfterPoolClose.pools[key].waiting === 0)) failures.push('pool-disposal');
  const samples = result.metrics?.samples;
  if (!Array.isArray(samples) || !samples.length || !samples.every(measuredSample)) failures.push('resource-samples');
  if (expected.action === 'run') {
    const cycles = result.checks.find((check) => check.name === 'fixed-workload-measured-cycles');
    if (cycles?.completed !== expected.cycles || cycles?.warmup !== expected.warmup) failures.push('completed-workload');
    if (!samples?.some((sample) => sample.phase === 'after-warmup')
      || !samples?.some((sample) => sample.phase === 'measured' && sample.cycle === expected.cycles)
      || !result.metrics?.memoryTrend?.values?.rss) failures.push('measured-memory-trend');
  }
  return failures;
}

export function readyMatches(record, expected) {
  const names = new Set(record?.checks?.filter((check) => check.status === 'PASS').map((check) => check.name));
  return record?.type === 'ready' && record.protocolVersion === 1 && provenanceMatches(record.runtime, expected)
    && Array.isArray(record.agents) && record.agents.length === 2 && new Set(record.agents).size === 2
    && record.agents.every((did) => /^did:key:z[1-9A-HJ-NP-Za-km-z]{20,100}$/.test(did))
    && [...COMMON, 'hold-two-real-agent-queries', 'hold-revocation-persisted-before-kill'].every((name) => names.has(name))
    && record.checks.every((check) => check.status === 'PASS')
    && record.counts?.length === 2 && record.counts.every((count) => count.agents === 1 && count.audit >= 1)
    && record.counts[0].revocations === 1 && record.counts[1].revocations === 0
    && record.metrics?.runtimes?.live === 2 && measuredSample(record.metrics);
}
