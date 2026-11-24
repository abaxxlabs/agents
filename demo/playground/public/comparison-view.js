import { createSvgIcon } from './icons.js';

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function renderPath(target, panel, protectedPath) {
  const agent = element('span', 'comparison-endpoint comparison-agent-endpoint absolute top-[6px] left-0 flex w-16 flex-col items-center gap-1');
  agent.append(createSvgIcon('agent'), element('span', `comparison-endpoint-label whitespace-nowrap text-[10px] leading-3 ${protectedPath ? 'text-comparison-teal' : 'text-comparison-text'}`, protectedPath ? 'Agents++' : 'Agent'));

  const connection = element('span', "comparison-connection absolute top-[28px] right-[86.5px] left-[60px] flex min-w-0 items-center justify-center before:absolute before:inset-x-0 before:h-px before:bg-current before:content-['']");
  const marker = protectedPath
    ? element('span', 'comparison-path-marker absolute flex size-[22px] items-center justify-center rounded-full bg-comparison-accent text-[10px] leading-3 text-comparison-surface', panel.state === 'allowed' ? '✓' : panel.state === 'blocked' ? '×' : '!')
    : element('span', 'comparison-path-label absolute flex h-[17px] w-[74px] items-center justify-center rounded-full bg-comparison-red text-center text-[10px] font-bold leading-3 text-comparison-surface', 'NO CHECKS');
  connection.appendChild(marker);

  const database = element('span', 'comparison-endpoint comparison-database-endpoint absolute top-[13px] right-[21.5px] flex w-16 flex-col items-center gap-[5px]');
  const faded = panel.state === 'error' || protectedPath && panel.state === 'blocked';
  database.append(createSvgIcon('database', faded ? 'opacity-35' : ''), element('span', `comparison-endpoint-label whitespace-nowrap text-[10px] leading-3 ${faded ? 'text-comparison-muted' : 'text-comparison-text'}`, 'Database'));
  target.className = 'comparison-path relative h-[58px] shrink-0 text-comparison-accent';
  target.setAttribute('aria-hidden', 'true');
  target.replaceChildren(agent, connection, database);
}

function renderMetrics(target, panel, prefix) {
  const tiles = panel.metrics.map((metric) => {
    const tile = element('div', 'comparison-metric');
    tile.dataset.metric = metric.key;
    const value = element('dd', `-order-1 text-left text-[15px] font-semibold leading-[19px] [overflow-wrap:anywhere] ${prefix === 'comparison-direct' && metric.key === 'rows' ? 'text-comparison-text' : 'text-comparison-accent'}`, metric.value);
    value.id = `${prefix}-${metric.key}`;
    if (metric.key === 'audit') setAuditReference(value, panel);
    tile.append(element('dt', 'text-[10px] font-normal leading-[11px] text-comparison-muted [overflow-wrap:anywhere] mobile:text-[12px] mobile:leading-4', metric.label), value);
    return tile;
  });
  target.replaceChildren(...tiles);
}

function setAuditReference(value, panel) {
  if (panel.auditId) value.title = `${panel.auditConfirmed ? 'Audit record' : 'Unconfirmed audit reference'}: ${panel.auditId}`;
  else value.removeAttribute('title');
}

function renderWarning(target, warning) {
  const current = target.querySelector('.comparison-warning');
  if (!warning) current?.remove();
  else if (current) current.textContent = warning;
  else target.appendChild(element('p', 'comparison-warning text-[12px] leading-[18px] text-pg-warning [overflow-wrap:anywhere]', warning));
}

export function renderAuditConfirmation(panel) {
  const value = document.getElementById('comparison-agent-audit');
  value.textContent = panel.auditConfirmed ? 'Saved' : 'Not confirmed';
  setAuditReference(value, panel);
  renderWarning(document.getElementById('comparison-agent-result'), panel.warning);
}

function cellText(value) {
  if (value === null) return 'NULL';
  if (value === undefined) return '—';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function resultTable(panel, protectedPath) {
  const columns = [...new Set(panel.rows.flatMap((row) => Object.keys(row)))];
  const restricted = new Set(protectedPath ? [] : panel.restrictedColumns);
  const region = element('div', 'comparison-table-scroll');
  region.tabIndex = 0;
  region.setAttribute('role', 'region');
  region.setAttribute('aria-label', protectedPath ? 'Agents++ query results' : 'Direct query results');
  const table = element('table', 'comparison-table w-full border-collapse text-left text-comparison-text');
  const count = `${panel.rows.length} ${panel.rows.length === 1 ? 'row' : 'rows'}`;
  table.appendChild(element('caption', 'comparison-sr-only absolute h-px w-px overflow-hidden whitespace-nowrap [clip-path:inset(50%)]', `${protectedPath ? 'Agents++' : 'Direct'} database response: ${count}`));
  const head = element('thead');
  const headings = element('tr');
  for (const column of columns) {
    const heading = element('th', `whitespace-nowrap ${column === 'instrument' ? 'w-[125px]' : column === 'price' ? 'w-[109px]' : ''} ${restricted.has(column) ? 'comparison-restricted' : ''}`, column);
    heading.scope = 'col';
    headings.appendChild(heading);
  }
  head.appendChild(headings);
  const body = element('tbody');
  for (const row of panel.rows) {
    const tr = element('tr');
    for (const column of columns) {
      const value = Object.prototype.hasOwnProperty.call(row, column) ? row[column] : undefined;
      tr.appendChild(element('td', `whitespace-nowrap ${restricted.has(column) ? 'comparison-restricted' : ''}`, cellText(value)));
    }
    body.appendChild(tr);
  }
  table.append(head, body);
  region.appendChild(table);
  return region;
}

function blockedResult(notice) {
  const card = resultCard('comparison-notice');
  const heading = element('div', 'flex flex-col items-center gap-2');
  heading.append(createSvgIcon('lock', 'text-comparison-teal'), element('h4', 'comparison-result-title text-[12px] font-semibold leading-4 text-comparison-accent', notice.title));
  card.append(
    heading,
    element('p', 'comparison-result-reason text-[12px] leading-[18px] text-comparison-text light:text-comparison-muted mobile:text-[13px] mobile:leading-5', notice.reason),
  );
  if (notice.policy) {
    const policy = element('p', 'comparison-policy flex min-w-0 flex-wrap items-center justify-center gap-1.5 text-[12px] leading-4 text-comparison-muted');
    policy.append(element('span', '', 'Policy'), element('code', 'max-w-full whitespace-pre-wrap rounded bg-comparison-inset px-1.5 py-1 text-[12px] leading-4 text-comparison-text ring-[0.6px] ring-inset ring-[var(--comparison-notice-border)] [overflow-wrap:anywhere]', notice.policy));
    card.appendChild(policy);
  }
  return card;
}

function operationResult(panel, sql) {
  const card = resultCard('comparison-operation gap-3 bg-comparison-tint p-4');
  const rows = panel.metrics.find((metric) => metric.key === 'rows');
  const summary = element('p', 'comparison-operation-summary flex flex-wrap items-baseline gap-x-[12px] gap-y-[8px] text-comparison-muted');
  summary.append(element('strong', 'text-[11px] text-comparison-red', panel.command), element('span', '', rows ? `${rows.label}: ${rows.value}` : ''));
  const query = element('pre', 'comparison-operation-sql max-w-full whitespace-pre-wrap rounded bg-comparison-inset p-2 text-[11px] leading-[18px] text-comparison-text [overflow-wrap:anywhere]');
  query.appendChild(element('code', '', sql));
  card.append(
    element('h4', 'comparison-result-title text-[13px] font-semibold leading-[20px] text-comparison-accent', panel.operation.title),
    summary,
    query,
    element('p', 'comparison-result-reason text-[12px] leading-[18px] text-comparison-muted', panel.operation.description),
  );
  return card;
}

function resultCard(className) {
  return element('div', `${className} flex min-h-[265px] min-w-0 flex-auto flex-col rounded-md [overflow-wrap:anywhere]`);
}

function renderResult(target, panel, protectedPath, sql) {
  let content;
  if (panel.state === 'error') {
    content = resultCard('comparison-error gap-3 bg-comparison-tint p-4');
    content.append(
      element('h4', 'comparison-result-title text-[13px] font-semibold leading-[20px] text-comparison-accent', 'Comparison unavailable'),
      element('p', 'comparison-result-reason text-[12px] leading-[18px] text-comparison-muted', panel.error || panel.status),
    );
  } else if (panel.state === 'blocked') {
    content = blockedResult(panel.notice);
  } else if (!protectedPath && panel.operation) {
    content = operationResult(panel, sql);
  } else if (panel.rows.length) {
    content = resultTable(panel, protectedPath);
  } else {
    content = element('p', 'comparison-empty flex min-h-[265px] min-w-0 flex-auto flex-col items-center justify-center gap-[12px] rounded-[6px] border border-comparison-border bg-comparison-inset p-[16px] text-comparison-muted [overflow-wrap:anywhere]', '0 rows');
  }
  target.replaceChildren(content);
  renderWarning(target, panel.warning);
}

function renderPanel(root, panel, protectedPath, sql) {
  const prefix = protectedPath ? 'comparison-agent' : 'comparison-direct';
  const article = root.querySelector(protectedPath ? '.comparison-protected' : '.comparison-direct');
  article.dataset.state = panel.state;
  root.querySelector(`#${prefix}-title`).textContent = panel.status;
  renderPath(root.querySelector(`#${prefix}-path`), panel, protectedPath);
  renderMetrics(root.querySelector(`#${prefix}-metrics`), panel, prefix);
  renderResult(root.querySelector(`#${prefix}-result`), panel, protectedPath, sql);
}

/** Render a comparison model into the existing comparison panels. */
export function renderComparison(model) {
  const root = document.getElementById('query-comparison');
  root.dataset.case = model.kind;
  renderPanel(root, model.direct, false, model.sql);
  renderPanel(root, model.scoped, true, model.sql);
}
