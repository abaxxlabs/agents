import assert from 'node:assert/strict';
import test from 'node:test';
import { assessVisitorDatabase } from '../scripts/cleanup-visitor-databases.mjs';

const eligible = {
  name: `agents_playground_visitor_${'a'.repeat(32)}`,
  owner: 'postgres',
  isTemplate: false,
  marker: 'agents-demo-playground',
  connections: 0,
  adminRole: 'postgres',
};

test('only marker-checked, idle, setup-owned visitor databases are eligible to drop', () => {
  assert.deepEqual(assessVisitorDatabase(eligible), { eligible: true });

  for (const [override, reason] of [
    [{ name: 'agents_playground_visitor_short' }, /name/],
    [{ isTemplate: true }, /template/],
    [{ owner: 'other_role' }, /owned/],
    [{ marker: null }, /marker/],
    [{ marker: 'foreign-owner' }, /marker/],
    [{ connections: 1 }, /connections/],
  ]) {
    const verdict = assessVisitorDatabase({ ...eligible, ...override });
    assert.equal(verdict.eligible, false);
    assert.match(verdict.reason, reason);
  }
});
