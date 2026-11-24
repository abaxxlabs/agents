import assert from 'node:assert/strict';
import test from 'node:test';
import { PREFIX, requireResult } from '../scripts/worker-routing-fencing-proof/report.mjs';
import { requiredChecks, driverEvidenceFailures } from '../scripts/worker-routing-fencing-proof/evidence.mjs';

const encoded = (value) => `${PREFIX}${JSON.stringify(value)}\n`;

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

test('a missing required check or any FAIL cannot pass', () => {
  const dropped = goodDriverResult();
  dropped.checks.pop();
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

test('the combined gate blocks when a prerequisite proof is not PASS', () => {
  const no887 = goodDriverResult();
  no887.acceptance.combinedGate.runtimeLifecycle887 = 'FAIL';
  assert.ok(driverEvidenceFailures(no887).includes('prerequisite-runtime-887'));
  const no888 = goodDriverResult();
  no888.acceptance.combinedGate.sqlIsolation888 = 'FAIL';
  assert.ok(driverEvidenceFailures(no888).includes('prerequisite-sql-888'));
});
