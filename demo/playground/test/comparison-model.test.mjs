import assert from 'node:assert/strict';
import test from 'node:test';
import { createComparisonModel } from '../public/comparison-model.js';

const AGENT = 'did:example:query-agent';
const AUDIT_ID = 'audit-current-query';
const KNOWN_COLUMNS = ['instrument', 'side', 'quantity', 'status', 'price', 'counterparty'];

function response(body, status = 200) {
  return { status, body };
}

function auditRecord(overrides = {}) {
  return { id: AUDIT_ID, agentDid: AGENT, status: 'success', ...overrides };
}

function fixture(overrides = {}) {
  return {
    request: {
      agent: AGENT,
      columns: ['orders.instrument', 'orders.quantity'],
      knownColumns: [...KNOWN_COLUMNS],
      sql: 'SELECT instrument, quantity FROM orders',
    },
    direct: response({ ok: true, command: 'SELECT', rows: [{ instrument: 'CONTRACT-A', quantity: 3 }] }),
    protectedPath: response({
      ok: true,
      rows: [{ instrument: 'CONTRACT-A', quantity: 3 }],
      metadata: { auditId: AUDIT_ID },
      inspection: { evidence: { authorization: 'allowed', auditId: AUDIT_ID } },
    }),
    auditRecords: [auditRecord()],
    ...overrides,
  };
}

function blockedFixture(overrides = {}) {
  return fixture({
    protectedPath: response({
      ok: false,
      inspection: { evidence: { authorization: 'rejected', error: 'SCOPE_VIOLATION', auditId: AUDIT_ID } },
    }, 403),
    auditRecords: [auditRecord({ status: 'rejected' })],
    ...overrides,
  });
}

function metrics(panel) {
  return Object.fromEntries(panel.metrics.map(({ key, value }) => [key, value]));
}

test('allowed custom projection preserves returned data and actual row counts', () => {
  const input = fixture();
  input.request.columns = ['orders.side', 'orders.status'];
  input.request.sql = 'SELECT side, status FROM orders WHERE quantity > 10';
  const rows = [{ side: 'buy', status: 'open' }, { side: 'sell', status: 'filled' }];
  input.direct.body.rows = rows;
  input.protectedPath.body.rows = rows.slice(0, 1);
  const model = createComparisonModel(input);

  assert.equal(model.kind, 'allowed');
  assert.equal(model.sql, input.request.sql);
  assert.equal(model.scoped.state, 'allowed');
  assert.deepEqual(model.direct.rows, rows);
  assert.deepEqual(model.scoped.rows, rows.slice(0, 1));
  assert.deepEqual(metrics(model.direct), { rows: 2, policy: 'None', audit: 'None' });
  assert.deepEqual(metrics(model.scoped), { rows: 1, policy: 'Passed', audit: 'Saved' });
  assert.deepEqual(model.direct.restrictedColumns, []);
  assert.equal(model.scoped.notice, null);
  assert.equal(model.scoped.warning, null);
});

test('scope rejection counts returned non-null restricted values, including falsey values', () => {
  const input = blockedFixture();
  input.request.sql = 'SELECT instrument, price, counterparty FROM orders';
  input.direct.body.rows = [
    { instrument: 'CONTRACT-A', price: 0, counterparty: '' },
    { instrument: 'CONTRACT-B', price: null, counterparty: false },
    { instrument: 'CONTRACT-C', price: undefined, counterparty: null },
  ];
  input.protectedPath.body.rows = [{ price: 'must not be presented' }];
  const model = createComparisonModel(input);

  assert.equal(model.kind, 'scope-blocked');
  assert.equal(model.scoped.state, 'blocked');
  assert.deepEqual(model.direct.restrictedColumns, ['price', 'counterparty']);
  assert.deepEqual(metrics(model.direct), { rows: 3, exposed: 3, audit: 'None' });
  assert.deepEqual(metrics(model.scoped), { rows: 0, exposed: 0, audit: 'Saved' });
  assert.deepEqual(model.scoped.rows, []);
  assert.match(model.scoped.notice.reason, /price, counterparty.*whole query was refused/);
  assert.equal(model.scoped.notice.policy, 'read: instrument, quantity');
});

test('restricted columns follow the issued custom scope rather than default column names', () => {
  const input = blockedFixture();
  input.request.sql = 'SELECT instrument, price, counterparty FROM orders';
  input.request.columns = ['orders.price', 'orders.counterparty'];
  input.direct.body.rows = [{ instrument: 'CONTRACT-A', price: 12, counterparty: 'PARTY-A' }];
  const model = createComparisonModel(input);

  assert.deepEqual(model.direct.restrictedColumns, ['instrument']);
  assert.equal(metrics(model.direct).exposed, 1);
  assert.equal(model.scoped.notice.policy, 'read: price, counterparty');
});

test('classification comes from an allowed response despite write SQL', () => {
  const input = fixture();
  input.request.sql = 'DELETE FROM orders';
  input.protectedPath = response({ ok: true,
    inspection: { evidence: { error: 'QUERY_REJECTED', auditId: AUDIT_ID } },
  });
  const model = createComparisonModel(input);

  assert.equal(model.kind, 'allowed');
  assert.equal(model.scoped.state, 'allowed');
});

test('success: audit confirmation requires the exact ID, agent and status in a single record', () => {
  const unrelated = [
    auditRecord({ id: 'unrelated-request', status: 'success' }),
    auditRecord({ agentDid: 'did:example:other-agent', status: 'success' }),
    auditRecord({ status: 'rejected' }),
  ];
  for (const auditRecords of [...unrelated.map((record) => [record]), unrelated]) {
    const model = createComparisonModel(fixture({ auditRecords }));

    assert.equal(model.scoped.state, 'allowed');
    assert.equal(model.scoped.auditId, AUDIT_ID);
    assert.equal(model.scoped.auditConfirmed, false);
    assert.equal(metrics(model.scoped).audit, 'Not confirmed');
    assert.ok(model.scoped.warning);
  }
  const input = fixture({ auditRecords: [...unrelated, auditRecord()] });
  const model = createComparisonModel(input);

  assert.equal(model.scoped.auditId, AUDIT_ID);
  assert.equal(model.scoped.auditConfirmed, true);
  assert.equal(metrics(model.scoped).audit, 'Saved');
  assert.equal(model.scoped.warning, null);
  assert.equal(model.direct.auditConfirmed, false);
  assert.equal(metrics(model.direct).audit, 'None');
});
