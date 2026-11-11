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

test('successful empty results stay allowed with zero rows and confirmed audit', () => {
  const input = fixture();
  input.direct.body.rows = [];
  input.protectedPath.body.rows = [];
  const model = createComparisonModel(input);

  assert.equal(model.kind, 'allowed');
  assert.equal(metrics(model.direct).rows, 0);
  assert.deepEqual(metrics(model.scoped), { rows: 0, policy: 'Passed', audit: 'Saved' });
  assert.equal(model.direct.operation, null);
  assert.deepEqual(model.scoped.rows, []);
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

test('aliased or derived result columns make exposure unavailable instead of inventing a count', () => {
  const input = blockedFixture();
  input.request.sql = 'SELECT price AS quoted_price, counterparty FROM orders';
  input.direct.body.rows = [{ quoted_price: 12, counterparty: 'PARTY-A' }];
  const model = createComparisonModel(input);

  assert.equal(model.kind, 'scope-blocked');
  assert.equal(metrics(model.direct).rows, 1);
  assert.equal(metrics(model.direct).exposed, 'Not available');
  assert.equal(metrics(model.scoped).exposed, 0);
  assert.doesNotMatch(model.direct.status, /data exposed/);
});

test('an alias matching an allowed column cannot conceal restricted values in the exposure metric', () => {
  const input = blockedFixture();
  input.request.sql = 'SELECT price AS instrument FROM orders';
  input.direct.body.rows = [{ instrument: 12.45 }];
  const model = createComparisonModel(input);

  assert.equal(metrics(model.direct).exposed, 'Not available');
  assert.deepEqual(model.direct.rows, [{ instrument: 12.45 }]);
  assert.deepEqual(model.direct.restrictedColumns, []);
  assert.equal(model.scoped.state, 'blocked');
});

test('an empty direct result does not fabricate exposed values for a scope rejection', () => {
  const input = blockedFixture();
  input.direct.body.rows = [];
  const model = createComparisonModel(input);

  assert.deepEqual(metrics(model.direct), { rows: 0, exposed: 0, audit: 'None' });
  assert.deepEqual(model.direct.restrictedColumns, []);
  assert.match(model.scoped.notice.reason, /no protected rows were returned/);
});

for (const command of ['DELETE', 'UPDATE']) {
  for (const rowCount of [0, 1, 4]) {
    test(`${command} shows the server's ${rowCount} affected rows and no invented order details`, () => {
      const input = blockedFixture({
        direct: response({ ok: true, command, rowCount }),
      });
      input.request.sql = command === 'DELETE'
        ? 'DELETE FROM orders WHERE id = 1'
        : 'UPDATE orders SET quantity = 7 WHERE id > 4';
      input.protectedPath.body.inspection.evidence.error = 'QUERY_REJECTED';
      const model = createComparisonModel(input);
      const verb = command === 'DELETE' ? 'deleted from' : 'updated in';

      assert.equal(model.kind, 'write-blocked');
      assert.equal(model.sql, input.request.sql);
      assert.equal(model.direct.command, command);
      assert.deepEqual(metrics(model.direct), { rows: rowCount, policy: 'None', audit: 'None' });
      assert.deepEqual(metrics(model.scoped), { rows: 0, policy: 'Failed', audit: 'Saved' });
      assert.equal(model.direct.metrics.find(({ key }) => key === 'rows').label,
        command === 'DELETE' ? 'Rows deleted' : 'Rows updated');
      assert.equal(model.direct.operation.title,
        `${rowCount} ${rowCount === 1 ? 'row' : 'rows'} ${verb} the demo sandbox`);
      assert.deepEqual(model.direct.rows, []);
      assert.deepEqual(model.scoped.rows, []);
      assert.match(model.scoped.notice.reason, new RegExp(`${command}.*SELECT-only`));
      assert.equal(model.scoped.notice.policy, 'allowed operations: SELECT');
    });
  }
}

test('a mutation without a reported affected count does not claim a row was changed', () => {
  const input = blockedFixture({ direct: response({ ok: true, command: 'DELETE' }) });
  input.protectedPath.body.inspection.evidence.error = 'QUERY_REJECTED';
  const model = createComparisonModel(input);

  assert.equal(metrics(model.direct).rows, 'Not available');
  assert.equal(model.direct.operation.title, 'Operation executed in the demo sandbox');
});

const classifications = [
  { name: 'allowed response despite write SQL', sql: 'DELETE FROM orders', status: 200, ok: true,
    code: 'QUERY_REJECTED', command: 'SELECT', kind: 'allowed', state: 'allowed' },
  { name: 'scope rejection despite allowed-preset SQL', status: 403, ok: false,
    code: 'SCOPE_VIOLATION', command: 'SELECT', kind: 'scope-blocked', state: 'blocked' },
  { name: 'write rejection despite SELECT input', status: 403, ok: false,
    code: 'QUERY_REJECTED', command: 'UPDATE', kind: 'write-blocked', state: 'blocked' },
  { name: 'non-write query rejection', status: 403, ok: false,
    code: 'QUERY_REJECTED', command: 'SELECT', kind: 'error', state: 'blocked' },
  { name: 'scope-like error on server failure', status: 500, ok: false,
    code: 'SCOPE_VIOLATION', command: 'SELECT', kind: 'error', state: 'error' },
  { name: 'HTTP success without operation success', status: 200, ok: false,
    code: undefined, command: 'SELECT', kind: 'error', state: 'error' },
];

for (const scenario of classifications) {
  test(`classification comes from actual responses: ${scenario.name}`, () => {
    const input = fixture();
    if (scenario.sql) input.request.sql = scenario.sql;
    input.direct.body.command = scenario.command;
    input.protectedPath = response({ ok: scenario.ok, message: 'Actual server result',
      inspection: { evidence: { error: scenario.code, auditId: AUDIT_ID } },
    }, scenario.status);
    const model = createComparisonModel(input);

    assert.equal(model.kind, scenario.kind);
    assert.equal(model.scoped.state, scenario.state);
    if (scenario.state !== 'allowed') assert.deepEqual(model.scoped.rows, []);
    if (scenario.state === 'error') {
      assert.equal(metrics(model.scoped).rows, '—');
      assert.equal(metrics(model.scoped).policy, 'Not confirmed');
      assert.equal(metrics(model.scoped).audit, 'Not confirmed');
      assert.equal(model.scoped.error, 'Actual server result');
    }
  });
}

test('a failed direct query does not masquerade as an empty successful query or leak its rows', () => {
  const model = createComparisonModel(blockedFixture({
    direct: response({ ok: false, command: 'SELECT', rows: [{ price: 5 }], message: 'Sandbox unavailable' }, 500),
  }));

  assert.equal(model.direct.state, 'error');
  assert.equal(model.direct.error, 'Sandbox unavailable');
  assert.deepEqual(model.direct.rows, []);
  assert.deepEqual(metrics(model.direct), { rows: '—', exposed: '—', audit: 'None' });
});

for (const outcome of ['success', 'rejected']) {
  const makeInput = outcome === 'success' ? fixture : blockedFixture;

  test(`${outcome}: audit confirmation finds the exact ID, agent and status among unrelated records`, () => {
    const input = makeInput({ auditRecords: [
      auditRecord({ id: 'unrelated-request', status: outcome }),
      auditRecord({ agentDid: 'did:example:other-agent', status: outcome }),
      auditRecord({ status: outcome === 'success' ? 'rejected' : 'success' }),
      auditRecord({ status: outcome }),
    ] });
    const model = createComparisonModel(input);

    assert.equal(model.scoped.auditId, AUDIT_ID);
    assert.equal(model.scoped.auditConfirmed, true);
    assert.equal(metrics(model.scoped).audit, 'Saved');
    assert.equal(model.scoped.warning, null);
    assert.equal(model.direct.auditConfirmed, false);
    assert.equal(metrics(model.direct).audit, 'None');
  });

  const unrelatedRecords = [
    ['different request ID', { id: 'other-request' }],
    ['different agent', { agentDid: 'did:example:other-agent' }],
    ['different status', { status: outcome === 'success' ? 'rejected' : 'success' }],
    ['missing ID', { id: undefined }],
    ['missing agent', { agentDid: undefined }],
    ['missing status', { status: undefined }],
  ];
  for (const [name, overrides] of unrelatedRecords) {
    test(`${outcome}: ${name} cannot confirm audit persistence`, () => {
      const model = createComparisonModel(makeInput({
        auditRecords: [auditRecord({ status: outcome, ...overrides })],
      }));

      assert.equal(model.scoped.auditConfirmed, false);
      assert.equal(metrics(model.scoped).audit, 'Not confirmed');
      assert.match(model.scoped.warning, /not been confirmed/);
    });
  }

  test(`${outcome}: separate records cannot collectively satisfy the audit correlation`, () => {
    const model = createComparisonModel(makeInput({ auditRecords: [
      auditRecord({ id: 'other-request', status: outcome }),
      auditRecord({ agentDid: 'did:example:other-agent', status: outcome }),
      auditRecord({ status: outcome === 'success' ? 'rejected' : 'success' }),
    ] }));

    assert.equal(metrics(model.scoped).audit, 'Not confirmed');
    assert.equal(model.scoped.auditConfirmed, false);
  });

  for (const auditId of [undefined, null, '', '   ', 42]) {
    test(`${outcome}: invalid response audit reference ${JSON.stringify(auditId)} stays unconfirmed`, () => {
      const input = makeInput();
      input.protectedPath.body.metadata = { auditId };
      input.protectedPath.body.inspection.evidence.auditId = auditId;
      const model = createComparisonModel(input);

      assert.equal(model.scoped.auditId, null);
      assert.equal(model.scoped.auditConfirmed, false);
      assert.equal(metrics(model.scoped).audit, 'Not confirmed');
    });
  }

  test(`${outcome}: an unavailable or failed audit GET supplies no proof but preserves the decision`, () => {
    const input = makeInput({ auditRecords: [] });
    const model = createComparisonModel(input);

    assert.equal(model.scoped.state, outcome === 'success' ? 'allowed' : 'blocked');
    assert.equal(model.scoped.auditId, AUDIT_ID);
    assert.equal(metrics(model.scoped).audit, 'Not confirmed');
    assert.deepEqual(model.scoped.rows, outcome === 'success' ? input.protectedPath.body.rows : []);
    delete input.auditRecords;
    assert.equal(createComparisonModel(input).scoped.auditConfirmed, false);
  });
}

test('allowed audit proof requires metadata.auditId rather than an inspection-only reference', () => {
  const input = fixture();
  delete input.protectedPath.body.metadata;
  const model = createComparisonModel(input);

  assert.equal(model.scoped.auditConfirmed, false);
  assert.equal(metrics(model.scoped).audit, 'Not confirmed');
});

test('rejected audit proof uses the inspection reference even when metadata has a different ID', () => {
  const input = blockedFixture();
  input.protectedPath.body.metadata = { auditId: 'unrelated-metadata-id' };
  const model = createComparisonModel(input);

  assert.equal(model.scoped.auditId, AUDIT_ID);
  assert.equal(model.scoped.auditConfirmed, true);
  assert.equal(metrics(model.scoped).audit, 'Saved');
});

test('rejected audit proof cannot fall back to metadata when the inspection reference is missing', () => {
  const input = blockedFixture();
  input.protectedPath.body.metadata = { auditId: AUDIT_ID };
  delete input.protectedPath.body.inspection.evidence.auditId;
  const model = createComparisonModel(input);

  assert.equal(model.scoped.auditConfirmed, false);
  assert.equal(metrics(model.scoped).audit, 'Not confirmed');
});
