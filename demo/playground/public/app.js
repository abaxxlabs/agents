import { renderAgentSdkPreview, renderSdkFlow } from './sdk-previews.js';
import { createQueryPresets } from './query-presets.js';
import { createComparisonModel } from './comparison-model.js';
import { renderComparison, renderAuditConfirmation } from './comparison-view.js';
import { renderAuditRecords } from './audit-view.js';

const state = {
  userAlias: null,
  human: null,
  agentDid: null,
  ownerAlias: null,
  ownerRole: null,
  agentOwnerDid: null,
  credential: null,
  credentialColumns: [],
};

const syncQueryPresets = createQueryPresets(() => state.credentialColumns, renderSdkFlow);

const ALL_COLUMNS = [
  { name: 'instrument', encrypted: false },
  { name: 'side', encrypted: false },
  { name: 'quantity', encrypted: false },
  { name: 'status', encrypted: false },
  { name: 'price', encrypted: true },
  { name: 'counterparty', encrypted: true },
];
const AUDIT_VISIBLE_LIMIT = 5;
const AUDIT_CONFIRMATION_TIMEOUT_MS = 5000;
let auditExpanded = false;
let comparisonVersion = 0;
let pendingAudit = null;

const $ = (id) => document.getElementById(id);

async function api(method, path, body, signal) {
  const res = await fetch(path, {
    method,
    headers: method === 'POST' ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });
  return { status: res.status, body: await res.json() };
}

function invalidateComparison() {
  comparisonVersion++;
  pendingAudit?.abort();
  pendingAudit = null;
}

function enable(stepId) {
  $(stepId).classList.remove('disabled');
}

function setResult(id, text, cls) {
  const el = $(id);
  el.textContent = text;
  el.classList.remove('mono', 'ok', 'err');
  if (cls) el.classList.add(cls);
}

function clearUserState() {
  invalidateComparison();
  Object.assign(state, {
    userAlias: null,
    human: null,
    agentDid: null,
    ownerAlias: null,
    ownerRole: null,
    agentOwnerDid: null,
    credential: null,
    credentialColumns: [],
  });
  syncQueryPresets();
  for (const id of ['step-agent', 'step-credential', 'step-query']) {
    $(id).classList.add('disabled');
  }
  for (const id of ['agent-result', 'credential-result']) {
    setResult(id, '');
  }
  $('query-comparison').hidden = true;
  $('comparison-status').textContent = '';
  $('comparison-direct-result').replaceChildren();
  $('comparison-agent-result').replaceChildren();
  $('query-implementation').open = false;
  $('decision-trace-output').replaceChildren();
  $('request-evidence-output').replaceChildren();
  $('comparison-direct-title').textContent = '';
  $('comparison-agent-title').textContent = '';
  $('credential-card').hidden = true;
  $('credential-card-columns').replaceChildren();
  agentNameTouched = false;
  resetAgentPreview();
  renderColumnPicker();
}

async function loadStatus() {
  try {
    const { body } = await api('GET', '/api/status');
    $('server-status').textContent = `● v${body.libraryVersion}`;
    $('server-status').classList.remove('err');
    $('server-status').classList.add('ok');
  } catch {
    $('server-status').textContent = '● server unavailable';
    $('server-status').classList.remove('ok');
    $('server-status').classList.add('err');
  }
}

$('btn-login').addEventListener('click', async () => {
  const checked = document.querySelector('input[name="human-did"]:checked');
  const humanDid = checked?.value;
  if (!humanDid) return setResult('login-result', 'select a demo identity', 'err');
  if (state.userAlias !== humanDid) clearUserState();
  const { status, body } = await api('POST', '/api/login', { humanDid });
  if (status !== 200) return setResult('login-result', body.message, 'err');
  state.human = body.humanDid;
  state.userAlias = humanDid;
  const c = body.ceiling;
  const card = checked.closest('label');
  const alias = card?.querySelector('.identity-name')?.textContent.trim() ?? humanDid;
  state.ownerAlias = alias;
  state.ownerRole = card?.querySelector('.identity-role')?.textContent.trim() ?? '';
  const ceilingTxt = c.columns.includes('*')
    ? 'ceiling: * (unrestricted)'
    : `ceiling: [${c.columns.map((x) => x.replace('orders.', '')).join(', ')}] (${c.resolvedFrom.join('/') || c.source})`;
  const result = $('login-result');
  result.classList.remove('err', 'mono');
  result.classList.add('ok');
  result.replaceChildren();
  const summary = document.createElement('span');
  summary.textContent = `✓ session: ${alias} (mock) · ${ceilingTxt}`;
  const didLine = document.createElement('span');
  didLine.className = 'login-did mt-[4px] block font-pg-mono text-[12px] leading-[18px] text-pg-subtle [overflow-wrap:anywhere]';
  didLine.textContent = body.humanDid;
  result.append(summary, didLine);
  enable('step-agent');
  await refreshAgents();
  await refreshAudit();
});

async function refreshAgents() {
  const { body } = await api('GET', `/api/agents?ownerDid=${encodeURIComponent(state.human)}`);
  if (!state.agentDid && body.agents.length) selectAgent(body.agents[0].did, body.agents[0].name);
}

function selectAgent(did, name, mode = 'reused') {
  state.agentDid = did;
  if (mode !== 'created') state.agentOwnerDid = state.human;
  const message = mode === 'reused'
    ? `✓ reusing existing agent: ${name}`
    : '✓ agent identity ready';
  setResult('agent-result', message, 'ok');
  $('agent-result').classList.add('mono');
  enable('step-credential');
  renderAgentPreview(did);
}

$('btn-create-agent').addEventListener('click', async () => {
  const name = $('agent-name').value.trim();
  const { status, body } = await api('POST', '/api/agents', { humanDid: state.human, name });
  if (status !== 201) return setResult('agent-result', body.message, 'err');
  state.agentOwnerDid = body.ownerDid ?? state.human;
  selectAgent(body.did, body.name, 'created');
  await refreshAgents();
});

function syncPreviewFromInput() {
  const name = $('agent-name').value.trim();
  renderAgentSdkPreview(name);
  $('credential-card-title').textContent = `Credential for ${name || 'agent'}`;
}

function resetAgentPreview() {
  $('agent-tech-grid').replaceChildren();
  const placeholder = document.createElement('p');
  placeholder.className = 'result text-[13px] leading-[20px] text-pg-muted';
  placeholder.textContent = 'create an agent to see its identity';
  $('agent-tech-grid').appendChild(placeholder);
  syncPreviewFromInput();
}

function techRow(label, value) {
  const row = document.createElement('div');
  row.className = 'tech-row mt-[10px] flex items-center gap-[10px] text-[12px] mobile:flex-wrap';
  const lab = document.createElement('span');
  lab.className = 'tech-label flex-[0_0_84px] font-bold text-pg-muted';
  lab.textContent = label;
  const code = document.createElement('code');
  code.className = 'rounded-[4px] bg-pg-control py-[2px] px-[6px] font-pg-mono text-[12px] leading-[18px] text-pg-text [overflow-wrap:anywhere]';
  code.textContent = value;
  row.append(lab, code);
  return row;
}

function renderAgentPreview(did) {
  const grid = $('agent-tech-grid');
  grid.replaceChildren();
  grid.appendChild(techRow('Agent DID', did));
  if (state.agentOwnerDid) grid.appendChild(techRow('Owner DID', state.agentOwnerDid));
}

let agentNameTouched = false;
const NAME_BY_IDENTITY = { alice: 'trading-assistant', bob: 'research-assistant' };

$('agent-name').addEventListener('input', () => {
  agentNameTouched = true;
  syncPreviewFromInput();
});

for (const radio of document.querySelectorAll('input[name="human-did"]')) {
  radio.addEventListener('change', () => {
    if (state.userAlias && state.userAlias !== radio.value) {
      clearUserState();
      setResult('login-result', 'identity changed; authenticate before creating an agent or issuing a credential', '');
    }
    const suggested = NAME_BY_IDENTITY[radio.value];
    if (!agentNameTouched && suggested) $('agent-name').value = suggested;
    syncPreviewFromInput();
  });
}

function renderColumnPicker() {
  const grid = $('columns-picker');
  grid.replaceChildren();
  for (const col of ALL_COLUMNS) {
    const label = document.createElement('label');
    label.className = 'col-chip flex min-h-[40px] cursor-pointer select-none items-center justify-between gap-[8px] rounded-[8px] bg-pg-control py-[10px] px-[12px] font-pg text-[13px] font-normal leading-[20px] text-pg-muted [border:0] has-[input:checked]:text-pg-text';
    const input = document.createElement('input');
    input.className = 'relative m-0 h-[16px] w-[16px] flex-[0_0_16px] appearance-none rounded-[2px] border border-pg-gray bg-pg-control p-0 font-pg text-[14px] leading-[20px] text-white accent-legacy-accent checked:border-pg-primary checked:bg-pg-primary checked:bg-checkbox-mark checked:bg-center checked:bg-no-repeat checked:bg-size-[12px_12px] focus:[outline:2px_solid_rgba(207,0,0,0.35)] focus:outline-offset-1 focus-visible:[outline:2px_solid_rgba(207,0,0,0.5)] focus-visible:outline-offset-2';
    input.type = 'checkbox';
    input.value = col.name;
    input.checked = ['instrument', 'side', 'quantity', 'status'].includes(col.name);
    const tag = document.createElement('span');
    tag.className = `tag ml-auto rounded-[4px] py-[2px] px-[8px] text-[11px] font-bold leading-[16px] ${col.encrypted ? 'enc bg-[rgba(239,68,68,0.1)] text-pg-error' : 'plain bg-[rgba(16,185,129,0.1)] text-pg-success'}`;
    tag.textContent = col.encrypted ? 'encrypted' : 'plain';
    label.append(input, document.createTextNode(`orders.${col.name}`), tag);
    grid.appendChild(label);
  }
  renderScopePreview();
}

function renderScopePreview() {
  const preview = $('scope-preview');
  preview.replaceChildren();
  const selected = [...document.querySelectorAll('#columns-picker input:checked')].map((i) => i.value);
  if (selected.some((name) => ALL_COLUMNS.find((c) => c.name === name)?.encrypted)) {
    const warn = document.createElement('span');
    warn.className = 'scope-warn text-[12px] font-normal leading-[18px] text-[rgba(239,68,68,0.8)]';
    warn.textContent = 'Requires encrypted-data access';
    preview.appendChild(warn);
  }
  preview.hidden = preview.childElementCount === 0;
}

function renderCredentialCard(columns, expiresAt) {
  const card = $('credential-card');
  syncPreviewFromInput();
  $('credential-card-scope').textContent = `READ · ${columns.length} FIELDS`;
  const columnList = $('credential-card-columns');
  columnList.replaceChildren();
  for (const column of columns) {
    const chip = document.createElement('span');
    chip.className = 'rounded-[4px] bg-[#1f2937] py-[6px] px-[8px] text-[10px] font-semibold leading-[12px] text-[#9ca3af]';
    chip.textContent = column.replace('orders.', '');
    columnList.appendChild(chip);
  }
  $('credential-card-expiry').textContent = `Expires at ${new Date(expiresAt * 1000).toLocaleTimeString()}`;
  card.hidden = false;
}

$('columns-picker').addEventListener('change', renderScopePreview);
document.querySelector('#columns-picker').addEventListener('change', renderSdkFlow);
document.querySelector('#credential-ttl').addEventListener('change', renderSdkFlow);
document.querySelector('#sql-input').addEventListener('input', renderSdkFlow);
renderColumnPicker();
renderSdkFlow();

$('btn-issue').addEventListener('click', async () => {
  const columns = [...document.querySelectorAll('#columns-picker input:checked')]
    .map((i) => `orders.${i.value}`);
  if (columns.length === 0) return setResult('credential-result', 'select at least one column', 'err');
  const { status, body } = await api('POST', '/api/credentials', {
    humanDid: state.human,
    agent: state.agentDid,
    columns,
    expiresIn: $('credential-ttl').value,
  });
  if (status !== 201) {
    return setResult('credential-result', `✗ ${body.error}: ${body.message}`, 'err');
  }
  invalidateComparison();
  state.credential = body.credential;
  const payload = JSON.parse(atob(body.credential.split('.')[1]));
  state.credentialColumns = payload.vc.credentialSubject.scope.columns;
  syncQueryPresets();
  setResult('credential-result',
    `✓ VC issued (jti ${payload.jti?.slice(0, 8)}…, expires ${new Date(payload.exp * 1000).toLocaleTimeString()})`,
    'ok');
  enable('step-query');
  renderCredentialCard(state.credentialColumns, payload.exp);
  $('query-comparison').hidden = true;
  $('comparison-status').textContent = '';
  $('comparison-direct-result').replaceChildren();
  $('comparison-agent-result').replaceChildren();
});

function directSqlForComparison(sql) {
  return sql.replace(/\b(from|join|update|into)\s+orders\b/gi, '$1 orders_plaintext');
}

function comparisonValue(body) {
  return body.message || body.error || 'Request failed';
}

function renderDecisionTrace(body, auditConfirmed) {
  const target = $('decision-trace-output');
  target.replaceChildren();
  for (const step of body.inspection?.decisionTrace ?? []) {
    const item = document.createElement('div');
    item.className = 'flex justify-between gap-[0.8rem] border-b border-b-legacy-border pb-1';
    item.textContent = !auditConfirmed && ['Audit recorded', 'Rejection recorded'].includes(step)
      ? 'Audit persistence not confirmed' : step;
    target.appendChild(item);
  }
}

function renderRequestEvidence(body, panel) {
  const target = $('request-evidence-output');
  target.replaceChildren();
  const evidence = body.inspection?.evidence ?? {};
  const values = [
    ['Authorization', evidence.authorization ?? '—'],
    ['Agent', evidence.agent ?? '—'],
    ['Audit ID', evidence.auditId ?? evidence.error ?? '—'],
    ['Audit status', panel.auditConfirmed ? 'Saved' : 'Not confirmed'],
    ['SQL', evidence.sql ?? '—'],
  ];
  for (const [label, value] of values) target.appendChild(techRow(label, value));
}

function comparisonStatus(panel) {
  return panel.state === 'allowed'
    ? panel.auditConfirmed ? 'Allowed and recorded' : 'Allowed; audit not confirmed'
    : panel.state === 'blocked' ? 'Access rejected' : 'Comparison failed';
}

async function confirmComparisonAudit(request, direct, protectedPath, isCurrent) {
  const controller = new AbortController();
  pendingAudit = controller;
  const timer = setTimeout(() => controller.abort(), AUDIT_CONFIRMATION_TIMEOUT_MS);
  try {
    const audit = await api('GET', '/api/audit', undefined, controller.signal).catch(() => null);
    if (!isCurrent() || controller.signal.aborted || audit?.status !== 200 || !Array.isArray(audit.body?.records)) return;
    const model = createComparisonModel({ request, direct, protectedPath, auditRecords: audit.body.records });
    renderAuditConfirmation(model.scoped);
    renderDecisionTrace(protectedPath.body, model.scoped.auditConfirmed);
    renderRequestEvidence(protectedPath.body, model.scoped);
    $('comparison-status').textContent = comparisonStatus(model.scoped);
    await refreshAudit(audit.body.records);
  } finally {
    clearTimeout(timer);
    if (pendingAudit === controller) pendingAudit = null;
  }
}

async function runComparison() {
  const button = $('btn-run');
  const sql = $('sql-input').value.trim();
  const columns = state.credentialColumns ?? [];
  if (!sql || !columns.length) return;
  invalidateComparison();
  const version = comparisonVersion;
  const request = {
    agent: state.agentDid,
    credential: state.credential,
    columns: [...columns],
    knownColumns: ALL_COLUMNS.map((column) => column.name),
    sql,
  };
  const isCurrent = () => version === comparisonVersion && state.agentDid === request.agent && state.credential === request.credential;
  button.disabled = true;
  button.textContent = 'Comparing…';
  $('query-comparison').setAttribute('aria-busy', 'true');
  $('comparison-status').textContent = 'Running both paths…';
  try {
    const reset = await api('POST', '/api/sim/reset');
    if (reset.status !== 200) throw new Error(comparisonValue(reset.body));
    const [direct, protectedPath] = await Promise.all([
      api('POST', '/api/sim/raw', { sql: directSqlForComparison(sql) }),
      api('POST', '/api/query', {
        agent: request.agent,
        credential: request.credential,
        sql,
        table: 'orders',
      }),
    ]);
    if (!isCurrent()) return;
    const model = createComparisonModel({ request, direct, protectedPath });
    renderComparison(model);
    renderDecisionTrace(protectedPath.body, model.scoped.auditConfirmed);
    renderRequestEvidence(protectedPath.body, model.scoped);
    $('query-implementation').open = false;
    $('query-comparison').hidden = false;
    $('comparison-status').textContent = comparisonStatus(model.scoped);
    void confirmComparisonAudit(request, direct, protectedPath, isCurrent);
  } catch (error) {
    if (!isCurrent()) return;
    const message = error instanceof Error ? error.message : 'Comparison failed';
    const unavailable = { status: 0, body: { message } };
    renderComparison(createComparisonModel({ request, direct: unavailable, protectedPath: unavailable }));
    $('comparison-status').textContent = 'Comparison failed';
    $('decision-trace-output').replaceChildren();
    $('request-evidence-output').replaceChildren();
    $('query-comparison').hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = 'Compare access';
    $('query-comparison').setAttribute('aria-busy', 'false');
  }
}

$('btn-run').addEventListener('click', runComparison);

async function refreshAudit(records) {
  if (!records) {
    const { status, body } = await api('GET', '/api/audit');
    if (status !== 200 || !Array.isArray(body?.records)) return;
    records = body.records;
  }
  const hiddenCount = Math.max(0, records.length - AUDIT_VISIBLE_LIMIT);
  const visible = auditExpanded ? records : records.slice(0, AUDIT_VISIBLE_LIMIT);
  renderAuditRecords(visible, auditExpanded ? 0 : hiddenCount, () => {
    auditExpanded = true;
    refreshAudit();
  });
}

$('btn-refresh-audit').addEventListener('click', () => {
  auditExpanded = false;
  refreshAudit();
});

$('btn-verify-chain').addEventListener('click', async () => {
  setResult('chain-result', 'verifying…');
  const { body } = await api('POST', '/api/audit/verify');
  if (body.ok) {
    setResult('chain-result', `✓ hash links checked (${body.totalRecords} records; signatures, completeness and deleted records not verified)`, 'ok');
  } else {
    setResult('chain-result', `✗ chain BROKEN: ${body.reason ?? JSON.stringify(body)}`, 'err');
  }
});

loadStatus();
syncPreviewFromInput();
