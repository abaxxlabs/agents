import { test, expect } from '@playwright/test';

function collectBrowserErrors(page, expectedForbidden = 0) {
  let forbidden = 0;
  const browserErrors = [];
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return;
    const expected = expectedForbidden > 0 && /Failed to load resource:.*403/.test(msg.text()) &&
      msg.location().url.endsWith('/api/query');
    if (expected) forbidden++;
    else browserErrors.push(msg.text());
  });
  page.on('pageerror', (error) => browserErrors.push(error.message));
  return async () => {
    await expect.poll(() => forbidden).toBe(expectedForbidden);
    expect(browserErrors).toEqual([]);
  };
}

async function setup(page) {
  await page.goto('/');
  await page.check('input[name="human-did"][value="alice"]');
  await page.click('#btn-login');
  await expect(page.locator('#step-agent')).not.toContainClass('disabled');
  const created = page.waitForResponse((res) => res.url().endsWith('/api/agents') && res.request().method() === 'POST');
  await page.click('#btn-create-agent');
  const agentResponse = await created;
  expect(agentResponse.status()).toBe(201);
  const agent = await agentResponse.json();
  await expect(page.locator('#step-credential')).not.toContainClass('disabled');
  await page.click('#btn-issue');
  await expect(page.locator('#step-query')).not.toContainClass('disabled');
  return agent;
}

async function compare(page, preset) {
  if (preset) await page.locator('#query-presets button').filter({ hasText: preset }).click();
  const pending = Promise.all(['/api/sim/raw', '/api/query', '/api/audit'].map((path) =>
    page.waitForResponse((res) => new URL(res.url()).pathname === path &&
      res.request().method() === (path === '/api/audit' ? 'GET' : 'POST'))));
  await page.click('#btn-run');
  const [direct, scoped, audit] = await pending;
  await expect(page.locator('#btn-run')).toBeEnabled();
  return {
    directStatus: direct.status(), direct: await direct.json(),
    status: scoped.status(), body: await scoped.json(), request: scoped.request().postDataJSON(),
    auditStatus: audit.status(), audit: await audit.json(),
  };
}

function correlatedAudit(result, agent, status) {
  const auditId = status === 'success' ? result.body.metadata?.auditId : result.body.inspection?.evidence?.auditId;
  expect(auditId).toEqual(expect.any(String));
  expect(auditId.trim()).not.toBe('');
  expect(result.request.agent).toBe(agent.did);
  expect(result.body.inspection.evidence.auditId).toBe(auditId);
  expect(result.auditStatus).toBe(200);
  expect(result.audit.records.filter((record) => record.id === auditId)).toEqual([
    expect.objectContaining({ id: auditId, agentDid: agent.did, status }),
  ]);
  return auditId;
}

async function expectSavedAudit(page, result, agent, status) {
  const auditId = correlatedAudit(result, agent, status);
  await expect(page.locator('#comparison-agent-audit')).toHaveText('Saved');
  await expect(page.locator('#comparison-agent-audit')).toHaveAttribute('title', `Audit record: ${auditId}`);
  await expect(page.locator('#request-evidence-output .tech-row').filter({ hasText: 'Audit ID' }).locator('code')).toHaveText(auditId);
}

async function expectBlocked(page, kind) {
  await expect(page.locator('#query-comparison')).toHaveAttribute('data-case', kind);
  await expect(page.locator('.comparison-protected')).toHaveAttribute('data-state', 'blocked');
  await expect(page.locator('#comparison-status')).toHaveText('Access rejected');
  await expect(page.locator('#comparison-agent-result .comparison-notice')).toBeVisible();
  await expect(page.locator('#comparison-agent-result .comparison-table')).toHaveCount(0);
  await expect(page.locator('#comparison-agent-rows')).toHaveText('0');
  await expect(page.locator('#decision-trace-output > *')).not.toHaveCount(0);
  await expect(page.locator('#request-evidence-output .tech-row:has-text("Authorization") code')).toHaveText('rejected');
}

async function holdNextAudit(page) {
  let release, reached, completed, held = false;
  const gate = new Promise((resolve) => { release = resolve; });
  const intercepted = new Promise((resolve) => { reached = resolve; });
  const finished = new Promise((resolve) => { completed = resolve; });
  const handler = async (route) => {
    if (held || route.request().method() !== 'GET') return route.continue();
    held = true;
    try {
      const response = await route.fetch();
      reached();
      await gate;
      if (!route.request().failure()) await route.fulfill({ response });
    } finally {
      completed();
    }
  };
  await page.route('**/api/audit', handler);
  return {
    intercepted,
    release,
    async dispose() {
      release();
      if (held) await finished;
      await page.unroute('**/api/audit', handler);
    },
  };
}

test('theme toggle updates appearance, accessibility state, and branding', async ({ page }) => {
  await page.goto('/');
  const toggle = page.getByRole('switch', { name: 'Light appearance' });
  const root = page.locator('html');
  const label = page.locator('#theme-label');
  const darkLogo = page.locator('[data-icon="brand-dark"]');
  const lightLogo = page.locator('[data-icon="brand-light"]');

  await expect(root).toHaveAttribute('data-theme', 'dark');
  await expect(toggle).toHaveAttribute('aria-checked', 'false');
  await expect(label).toHaveText('Dark');
  await expect(darkLogo).toBeVisible();
  await expect(lightLogo).toBeHidden();

  await toggle.click();
  await expect(root).toHaveAttribute('data-theme', 'light');
  await expect(toggle).toHaveAttribute('aria-checked', 'true');
  await expect(label).toHaveText('Light');
  await expect(lightLogo).toBeVisible();
  await expect(darkLogo).toBeHidden();

  await toggle.click();
  await expect(root).toHaveAttribute('data-theme', 'dark');
  await expect(toggle).toHaveAttribute('aria-checked', 'false');
  await expect(label).toHaveText('Dark');
  await expect(darkLogo).toBeVisible();
  await expect(lightLogo).toBeHidden();
});

test('allowed query returns protected data, evidence, and an audit record', async ({ page }) => {
  const checkConsole = collectBrowserErrors(page);
  const agent = await setup(page);
  const result = await compare(page, 'allowed columns');

  expect(result.status).toBe(200);
  expect(result.body.ok).toBe(true);
  expect(result.body.rows).toHaveLength(8);
  expect(result.directStatus).toBe(200);
  expect(result.direct.command).toBe('SELECT');
  expect(result.direct.rows).toHaveLength(8);
  await expect(page.locator('#query-comparison')).toHaveAttribute('data-case', 'allowed');
  await expect(page.locator('.comparison-protected')).toHaveAttribute('data-state', 'allowed');
  await expect(page.locator('#comparison-status')).toHaveText('Allowed and recorded');
  await expect(page.locator('#comparison-agent-result .comparison-table tbody tr')).toHaveCount(8);
  await expect(page.locator('#comparison-agent-result .comparison-table')).toBeVisible();
  await expect(page.locator('#comparison-agent-result tbody tr').first().locator('td'))
    .toHaveText(Object.values(result.body.rows[0]).map(String));
  await expect(page.locator('#comparison-direct-rows')).toHaveText('8');
  await expect(page.locator('#comparison-agent-rows')).toHaveText('8');
  await expect(page.locator('#comparison-agent-policy')).toHaveText('Passed');
  await expect(page.locator('.comparison-restricted')).toHaveCount(0);
  await expect(page.locator('#decision-trace-output > *')).not.toHaveCount(0);
  await expect(page.locator('#request-evidence-output .tech-row:has-text("Authorization") code')).toHaveText('allowed');
  await expectSavedAudit(page, result, agent, 'success');
  await checkConsole();
});

test('out-of-scope query is rejected without returning protected data', async ({ page }) => {
  const checkConsole = collectBrowserErrors(page, 1);
  const agent = await setup(page);
  const result = await compare(page, 'outside scope');

  expect(result.status).toBe(403);
  expect(result.body.ok).toBe(false);
  expect(result.body.rows).toBeUndefined();
  expect(result.body.inspection.evidence.error).toBe('SCOPE_VIOLATION');
  expect(result.directStatus).toBe(200);
  expect(result.direct.rows).toHaveLength(8);
  await expectBlocked(page, 'scope-blocked');
  await expect(page.locator('#comparison-direct-result .comparison-table')).toBeVisible();
  await expect(page.locator('#comparison-direct-result th.comparison-restricted')).toHaveText(['price', 'counterparty']);
  await expect(page.locator('#comparison-direct-result td.comparison-restricted')).toHaveCount(16);
  await expect(page.locator('#comparison-direct-exposed')).toHaveText('16');
  await expect(page.locator('#comparison-agent-exposed')).toHaveText('0');
  await expectSavedAudit(page, result, agent, 'rejected');
  await checkConsole();
});

test('write attempt is discarded and the next comparison sees the canonical fixture', async ({ page }) => {
  const checkConsole = collectBrowserErrors(page, 1);
  const agent = await setup(page);
  const result = await compare(page, 'write attempt');

  expect(result.directStatus).toBe(200);
  expect(result.direct).toEqual({ ok: true, command: 'DELETE', rowCount: 1 });
  expect(result.status).toBe(403);
  expect(result.body.rows).toBeUndefined();
  expect(result.body.inspection.evidence.error).toBe('QUERY_REJECTED');
  expect(result.request.sql).toBe('DELETE FROM orders WHERE id = 1');
  await expectBlocked(page, 'write-blocked');
  await expect(page.locator('#comparison-direct-rows')).toHaveText('1');
  await expect(page.locator('#comparison-agent-policy')).toHaveText('Failed');
  await expect(page.locator('#comparison-direct-result .comparison-operation .comparison-result-title'))
    .toHaveText('1 row deleted from the per-request copy');
  await expect(page.locator('.comparison-operation-sql code')).toHaveText(result.request.sql);
  await expect(page.locator('#comparison-direct-result .comparison-table')).toHaveCount(0);
  await expect(page.locator('#comparison-direct-result')).not.toContainText('LNG-JKM-SEP26');
  await expectSavedAudit(page, result, agent, 'rejected');

  const after = await compare(page, 'allowed columns');
  expect(after.status).toBe(200);
  expect(after.direct.rows).toHaveLength(8);
  expect(after.body.rows).toHaveLength(8);
  expect(after.body.rows.some((row) => row.instrument === 'LNG-JKM-SEP26')).toBe(true);
  await expect(page.locator('#query-comparison')).toHaveAttribute('data-case', 'allowed');
  await expect(page.locator('#comparison-direct-rows')).toHaveText('8');
  await expect(page.locator('#comparison-agent-rows')).toHaveText('8');
  await expect(page.locator('.comparison-operation, .comparison-notice')).toHaveCount(0);
  await expectSavedAudit(page, after, agent, 'success');
  await checkConsole();
});

test('an older audit response cannot overwrite a newer comparison using the same credential', async ({ page }) => {
  const checkConsole = collectBrowserErrors(page);
  const agent = await setup(page);
  const audit = await holdNextAudit(page);
  try {
    await page.locator('#query-presets button.good').click();
    await page.locator('#btn-run').click();
    await audit.intercepted;
    await expect(page.locator('#comparison-agent-result th')).toHaveText(['instrument', 'side', 'quantity', 'status']);
    await expect(page.locator('#btn-run')).toBeEnabled();

    await page.fill('#sql-input', 'SELECT status FROM orders');
    const current = await compare(page);
    await expectSavedAudit(page, current, agent, 'success');
    await expect(page.locator('#comparison-agent-result th')).toHaveText(['status']);
    const title = await page.locator('#comparison-agent-audit').getAttribute('title');
    await audit.dispose();

    await expect(page.locator('#comparison-agent-result th')).toHaveText(['status']);
    await expect(page.locator('#comparison-agent-audit')).toHaveAttribute('title', title);
    await expect(page.locator('#request-evidence-output .tech-row').filter({ hasText: 'SQL' }).locator('code'))
      .toHaveText('SELECT status FROM orders');
  } finally {
    await audit.dispose();
  }
  await checkConsole();
});

test('a stalled audit lookup times out without hiding query data or claiming it was saved', async ({ page }) => {
  const checkConsole = collectBrowserErrors(page);
  await setup(page);
  await page.clock.install();
  const audit = await holdNextAudit(page);
  try {
    await page.locator('#query-presets button.good').click();
    const response = page.waitForResponse((res) => res.url().endsWith('/api/query') && res.request().method() === 'POST');
    await page.locator('#btn-run').click();
    expect((await response).status()).toBe(200);
    await audit.intercepted;
    await expect(page.locator('#comparison-agent-result tbody tr')).toHaveCount(8);
    await expect(page.locator('#btn-run')).toBeEnabled();
    const aborted = page.waitForEvent('requestfailed', { predicate: (request) => request.url().endsWith('/api/audit') });
    await page.clock.fastForward(6000);
    expect((await aborted).failure().errorText).toBe('net::ERR_ABORTED');
    await audit.dispose();

    await expect(page.locator('#comparison-agent-result tbody tr')).toHaveCount(8);
    await expect(page.locator('#comparison-agent-audit')).toHaveText('Not confirmed');
    await expect(page.locator('#comparison-status')).toHaveText('Allowed; audit not confirmed');
    await expect(page.locator('#btn-run')).toBeEnabled();
  } finally {
    await audit.dispose();
  }
  await checkConsole();
});
