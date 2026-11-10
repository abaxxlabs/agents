import assert from 'node:assert/strict';
import test from 'node:test';
import {
  PREFIX, parseRecords, requireResult, finalizeReport,
} from '../scripts/worker-routing-fencing-proof/report.mjs';
import {
  REQUIRED, requiredChecks, driverEvidenceFailures, workerEvidenceFailures, provenanceMatches,
} from '../scripts/worker-routing-fencing-proof/evidence.mjs';

const encoded = (value) => `${PREFIX}${JSON.stringify(value)}\n`;

// A full driver result that satisfies the fail-closed evidence contract.
const goodDriverResult = () => ({
  type: 'result', protocol: 1, status: 'PASS',
  checks: requiredChecks().map((name) => ({ name, status: 'PASS' })),
  acceptance: {
    combinedGate: { routingDrainingFencing: true, staleOwnerSafety: true,
      runtimeLifecycle887: 'PASS', sqlIsolation888: 'PASS' },
  },
  workloadAuth: {
    productionRequirement: 'mTLS-or-SPIFFE-required',
    claimed: false,
  },
});

// A full worker (serve) result with clean provenance + cleanup.
const goodWorkerResult = (worker) => ({
  type: 'result', protocol: 1, status: 'PASS', worker,
  checks: [{ name: 'worker-ready', status: 'PASS' }],
  runtime: { node: 'v22.13.0', platform: 'linux', uid: 1000 },
  poolError: false,
  cleanup: { status: 'PASS', resources: [{ resource: 'http-server', status: 'PASS' }] },
});

test('the evidence contract lists a disjoint, non-empty required set', () => {
  const all = requiredChecks();
  assert.ok(all.length >= 140, `expected the full matrix, got ${all.length}`);
  const groups = Object.entries(REQUIRED);
  const seen = new Set();
  for (const [, names] of groups) for (const n of names) {
    assert.ok(!seen.has(n), `duplicate required check: ${n}`);
    seen.add(n);
  }
  assert.equal(seen.size, all.length, 'group union must equal requiredChecks()');
});

test('requireResult rejects malformed or duplicated protocol records', () => {
  assert.throws(() => requireResult('native module could not load', 1));
  assert.throws(() => requireResult(encoded({ type: 'sample' }), 0));
  assert.throws(() => requireResult(encoded(goodDriverResult()) + encoded(goodDriverResult()), 0));
  assert.throws(() => parseRecords(`${PREFIX}{malformed\n`));
  // Two result records of different workers are NOT two driver results.
  assert.throws(() => requireResult(encoded({ ...goodDriverResult(), worker: 'a' }) + encoded({ ...goodDriverResult(), worker: 'b' }), 0));
});

test('a missing required check or any FAIL cannot pass', () => {
  const dropped = goodDriverResult();
  dropped.checks.pop(); // one fewer than required
  const checked = requireResult(encoded(dropped), 0);
  assert.equal(checked.status, 'FAIL');
  assert.ok(checked.evidenceFailures.some((f) => f.startsWith('missing-pass:')));

  const failed = goodDriverResult();
  failed.checks[0].status = 'FAIL';
  const checked2 = requireResult(encoded(failed), 0);
  assert.equal(checked2.status, 'FAIL');
  assert.ok(checked2.evidenceFailures.includes(`failed:${failed.checks[0].name}`));
});

test('non-zero exit or FAIL status forces FAIL even if every check passes', () => {
  assert.equal(requireResult(encoded(goodDriverResult()), 2).status, 'FAIL');
  const fail = { ...goodDriverResult(), status: 'FAIL' };
  assert.equal(requireResult(encoded(fail), 0).status, 'FAIL');
});

test('a workload-auth claim that asserts (not states) sufficiency cannot pass', () => {
  const claimed = goodDriverResult();
  claimed.workloadAuth.claimed = true;
  assert.ok(driverEvidenceFailures(claimed).includes('workload-auth-not-stated'));
});

test('the combined gate blocks when a prerequisite proof is not PASS', () => {
  const no887 = goodDriverResult();
  no887.acceptance.combinedGate.runtimeLifecycle887 = 'FAIL';
  assert.ok(driverEvidenceFailures(no887).includes('prerequisite-runtime-887'));
  const no888 = goodDriverResult();
  no888.acceptance.combinedGate.sqlIsolation888 = 'FAIL';
  assert.ok(driverEvidenceFailures(no888).includes('prerequisite-sql-888'));
});

test('driverEvidenceFailures returns no failure for a fully conforming result', () => {
  assert.deepEqual(driverEvidenceFailures(goodDriverResult()), []);
});

test('workerEvidenceFailures enforces provenance, cleanup, and pool errors', () => {
  assert.deepEqual(workerEvidenceFailures(goodWorkerResult('worker-a')), []);

  const wrongNode = goodWorkerResult('a');
  wrongNode.runtime.node = 'v24.18.0';
  assert.ok(workerEvidenceFailures(wrongNode).includes('image-runtime-provenance'));

  const rootUid = goodWorkerResult('a');
  rootUid.runtime.uid = 0;
  assert.ok(workerEvidenceFailures(rootUid).includes('image-runtime-provenance'));

  const poolErr = goodWorkerResult('a');
  poolErr.poolError = true;
  assert.ok(workerEvidenceFailures(poolErr).includes('idle-pool-errors'));

  const badCleanup = goodWorkerResult('a');
  badCleanup.cleanup.resources.push({ resource: 'pool-control', status: 'FAIL' });
  badCleanup.cleanup.status = 'FAIL';
  const f = workerEvidenceFailures(badCleanup);
  assert.ok(f.includes('worker-cleanup'));
  assert.ok(f.includes('cleanup:pool-control'));
});

test('provenanceMatches only accepts node 22, linux, unprivileged uid', () => {
  assert.equal(provenanceMatches({ node: 'v22.13.0', platform: 'linux', uid: 1000 }), true);
  assert.equal(provenanceMatches({ node: 'v22.13.0', platform: 'darwin', uid: 1000 }), false);
  assert.equal(provenanceMatches({ node: 'v20.11.0', platform: 'linux', uid: 1000 }), false);
  assert.equal(provenanceMatches({ node: 'v22.13.0', platform: 'linux', uid: 0 }), false);
  assert.equal(provenanceMatches(undefined), false);
});

test('finalizeReport produces a 6-criterion acceptance + combined go/no-go', () => {
  const report = {
    protocol: 1, status: 'PASS',
    phases: {
      driver: { status: 'PASS', acceptance: { routingMatrix: true, drain: true, deadOwner: true, fencing: true, forgedHop: true },
        combinedGate: { routingDrainingFencing: true, staleOwnerSafety: true, runtimeLifecycle887: 'PASS', sqlIsolation888: 'PASS' } },
      'worker-a': { status: 'PASS', cleanup: 'PASS' },
      'worker-b': { status: 'PASS', cleanup: 'PASS' },
    },
  };
  const finalized = finalizeReport(report);
  assert.equal(finalized.acceptance.length, 6);
  assert.deepEqual(finalized.acceptance.map((a) => a.status), ['PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS']);
  assert.equal(finalized.combinedGate.go, true);
  // The gate consumes the DRIVER's prerequisite verdicts (W3), not a
  // hardcoded PASS.
  assert.equal(finalized.combinedGate.runtimeLifecycle887, 'PASS');
  assert.equal(finalized.combinedGate.sqlIsolation888, 'PASS');

  // A worker that did not clean up flips the gate to NO-GO.
  report.phases['worker-b'] = { status: 'PASS', cleanup: 'FAIL' };
  const ng = finalizeReport(report);
  assert.equal(ng.combinedGate.go, false);
  assert.ok(ng.combinedGate.workerShutdown === false);
});

test('finalizeReport blocks go when a prerequisite proof is not PASS', () => {
  const noPrereq = finalizeReport({
    protocol: 1, status: 'PASS',
    phases: {
      driver: { status: 'PASS', acceptance: { routingMatrix: true, drain: true, deadOwner: true, fencing: true, forgedHop: true },
        combinedGate: { routingDrainingFencing: true, staleOwnerSafety: true, runtimeLifecycle887: 'FAIL', sqlIsolation888: 'PASS' } },
      'worker-a': { status: 'PASS', cleanup: 'PASS' },
      'worker-b': { status: 'PASS', cleanup: 'PASS' },
    },
  });
  assert.equal(noPrereq.acceptance[5].status, 'NOT_PROVEN');
  assert.equal(noPrereq.combinedGate.go, false);
  assert.equal(noPrereq.combinedGate.runtimeLifecycle887, 'FAIL');
});

test('finalizeReport blocks go when the driver gate is not proven', () => {
  const report = {
    protocol: 1, status: 'PASS',
    phases: {
      driver: { status: 'PASS', acceptance: { routingMatrix: true, drain: true, deadOwner: false, fencing: true, forgedHop: true } },
      'worker-a': { status: 'PASS', cleanup: 'PASS' },
      'worker-b': { status: 'PASS', cleanup: 'PASS' },
    },
  };
  const finalized = finalizeReport(report);
  // deadOwner=false -> staleOwnerSafety false -> combined gate false.
  assert.equal(finalized.acceptance[5].status, 'NOT_PROVEN');
  assert.equal(finalized.combinedGate.go, false);
});
