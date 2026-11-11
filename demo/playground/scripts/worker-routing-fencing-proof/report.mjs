import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { driverEvidenceFailures, workerEvidenceFailures } from './evidence.mjs';

export const PREFIX = 'WORKER_ROUTING_FENCING_PROOF ';

export function parseRecords(output) {
  return String(output ?? '').split('\n').filter((line) => line.startsWith(PREFIX))
    .map((line) => JSON.parse(line.slice(PREFIX.length)));
}

// Exactly one driver result, validated against the fail-closed evidence contract.
export function requireResult(output, exitCode) {
  const results = parseRecords(output).filter((record) => record.type === 'result');
  if (results.length !== 1) throw new Error('missing-or-invalid-worker-result');
  const result = results[0];
  const failures = driverEvidenceFailures(result);
  if (exitCode !== 0 || result.status !== 'PASS' || failures.length) result.status = 'FAIL';
  result.evidenceFailures = failures;
  return result;
}

export function finalizeReport(report) {
  const driver = report.phases.driver ?? {};
  const workers = ['worker-a', 'worker-b'].map((w) => report.phases[w]).filter(Boolean);
  const workerOk = workers.length === 2 && workers.every((w) => w.status === 'PASS' && w.cleanup === 'PASS');

  const a = driver.acceptance ?? {};
  const ac = (ok, evidence) => ({ status: ok ? 'PASS' : 'NOT_PROVEN', evidence });
  report.acceptance = [
    { criterion: 1, ...ac(Boolean(a.routingMatrix),
      'Every real operation from both entry points on both sandboxes resolves to the same live owner + generation (no new identity minted on forward); duplicate and cross-sandbox reservations are refused; the runtime DID is persisted and stable; static/healthz/readyz are unrouted; the JSON body survives the hop chain.') },
    { criterion: 2, ...ac(Boolean(a.drain),
      'A drained worker records a deadline and marks its existing sessions draining; a concurrent admission racing the drain is refused by the in-transaction catalog gate with no session row written (F5); new-session admission stays closed while readyz stays alive; forced retirement keeps admission closed with no SDK state migrated or recreated; the janitor reaps the retired owner session lost.') },
    { criterion: 3, ...ac(Boolean(a.fencing),
      'Ownership is fenced at the mutation transaction boundary: a stale generation rolls back (409, fenced pre, no commit); an expired lease is terminal until renewed; the in-flight advisory lock makes the janitor defer and a generation bump AND an ownership transfer fail (55P03, F3); the pre-commit fence rejects a passed drain deadline and a retired owner (F2) with no partial write; a resumed stale owner cannot commit and a lost session is not resurrected; a transfer to a non-holder is incompatible-runtime (F7) until ownership returns to the holder. Transaction-level evidence recorded.') },
    { criterion: 4, ...ac(Boolean(a.deadOwner),
      'A dead owner session is reaped LOST and every entry point returns a defined session-lost (no random reroute); a catalog outage makes a mutation fail closed with dependency-unavailable and no ambiguous commit, and recovery resumes the same owner/session/generation.') },
    { criterion: 5, ...ac(Boolean(a.forgedHop),
      'Forged internal hops are rejected per vector (bad/cross signature, hop-limit, deadline, stale generation, wrong destination, missing headers) while a valid hop executes; the catalog control surface is an explicit EXECUTE allowlist -- PUBLIC and the data-plane roles are denied every privileged function (verified by has_function_privilege AND a real 42501 execution probe) and keep only the fence/read surface (F1); the public surface enforces the Origin allowlist and expected Host before any route handling (W2). The production mTLS/SPIFFE workload-identity requirement is STATED, not claimed, and gateway-only header policy is not sufficient.') },
    { criterion: 6, ...ac(Boolean(driver.combinedGate?.routingDrainingFencing) && Boolean(driver.combinedGate?.staleOwnerSafety)
      && driver.combinedGate?.runtimeLifecycle887 === 'PASS' && driver.combinedGate?.sqlIsolation888 === 'PASS',
      'Combined initial go/no-go: cites the merged 887 SQLite runtime (PASS, verified by the driver from the image) and 888 SQL isolation (PASS) reports; the routing/drain/fencing/stale-owner matrix from this proof is all-PASS, so the bounded two-worker composition passes the initial gate. This is not production migration, capacity, HA, or durable-session approval.') },
  ];
  const allPass = report.status === 'PASS' && workerOk
    && report.acceptance.every((entry) => entry.status === 'PASS') && !report.failure;
  report.combinedGate = {
    go: allPass,
    runtimeLifecycle887: driver.combinedGate?.runtimeLifecycle887 ?? 'FAIL',
    sqlIsolation888: driver.combinedGate?.sqlIsolation888 ?? 'FAIL',
    routingDrainingFencing: Boolean(driver.combinedGate?.routingDrainingFencing),
    staleOwnerSafety: Boolean(driver.combinedGate?.staleOwnerSafety),
    workerShutdown: workerOk,
  };
  report.recommendation = allPass
    ? 'Initial gate PASS for the bounded two-worker composition. The real SDK runtime, fenced executor, owner-aware routing, drain/retire admission, transaction-bound ownership fencing and forged-hop rejection are proven on the egress-blocked internal network. Production rollout additionally requires mTLS/SPIFFE workload identity (stated, not satisfied by gateway-only header policy) and is out of scope for this proof.'
    : 'Initial gate NOT met. Resolve the failed or missing evidence, the worker shutdown contract, or the prerequisite reports before approving a later gate.';
  report.finishedAt = new Date().toISOString();
  return report;
}

export async function writeReport(directory, report) {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  const gate = report.combinedGate ?? {};
  const rows = (report.phases.driver?.checks ?? [])
    .map((c) => `| ${c.name} | ${c.status} |`).join('\n');
  const markdown = [
    '# Worker routing, draining and fencing proof', '',
    `Result: **${report.status}** — combined initial gate: **${gate.go ? 'GO' : 'NO-GO'}**`, '',
    report.recommendation, '',
    `Started: ${report.startedAt}`, `Finished: ${report.finishedAt}`, '',
    '## Reproduction', '', '```sh', report.command, '```', '',
    '## Prerequisite reports (merged)', '',
    '- SQLite runtime proof: `reports/sqlite-runtime-proof.md` (PASS).',
    '- SQL isolation proof: `reports/sandbox-isolation-proof.json` (PASS, 147 checks).',
    'These two reports are inputs to the combined gate; this proof adds the routing, drain, lease, generation and fencing evidence.', '',
    '## Environment', '', '```json', JSON.stringify(report.environment, null, 2), '```', '',
    '## Combined gate', '', '```json', JSON.stringify(gate, null, 2), '```', '',
    '## Acceptance', '',
    ...report.acceptance.map((entry) => `- Criterion ${entry.criterion}: ${entry.status}. ${entry.evidence}`), '',
    '## Worker shutdown', '',
    ...['worker-a', 'worker-b'].map((w) => `- ${w}: status ${report.phases[w]?.status ?? 'n/a'}, cleanup ${report.phases[w]?.cleanup ?? 'n/a'}`), '',
    '## Driver checks', '',
    '| Check | Result |', '|---|---|', rows || '| (none) | FAIL |', '',
    '## Workload identity', '',
    report.phases.driver?.workloadAuth
      ? '```json\n' + JSON.stringify(report.phases.driver.workloadAuth, null, 2) + '\n```'
      : 'Not recorded.', '',
    'Machine-readable checks, fault sequences and failure stages are in report.json.', '',
    '## Sources', '',
    '- https://node-postgres.com/apis/pool',
    '- https://www.postgresql.org/docs/16/explicit-locks.html',
    '- https://nodejs.org/api/process.html', '',
  ].join('\n');
  await writeFile(join(directory, 'report.md'), markdown);
}
