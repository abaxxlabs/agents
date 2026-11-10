function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function icon(kind) {
  const namespace = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(namespace, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.5');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const shapes = kind === 'database'
    ? [
      ['ellipse', { cx: '12', cy: '5', rx: '7', ry: '3' }],
      ['path', { d: 'M5 5v14c0 1.66 3.13 3 7 3s7-1.34 7-3V5' }],
      ['path', { d: 'M5 10c0 1.66 3.13 3 7 3s7-1.34 7-3M5 15c0 1.66 3.13 3 7 3s7-1.34 7-3' }],
    ]
    : [
      ['rect', { x: '5', y: '10', width: '14', height: '11', rx: '2' }],
      ['path', { d: 'M8 10V7a4 4 0 0 1 8 0v3M12 14v3' }],
    ];
  for (const [tag, attributes] of shapes) {
    const shape = document.createElementNS(namespace, tag);
    for (const [name, value] of Object.entries(attributes)) shape.setAttribute(name, value);
    svg.appendChild(shape);
  }
  return svg;
}

function renderPath(target, panel, protectedPath) {
  const agent = element('span', 'comparison-endpoint comparison-agent-endpoint flex min-w-0 flex-[0_0_60px] flex-col items-center gap-[3px]');
  const frame = element('span', 'comparison-agent-icon-frame relative block h-[30px] w-[30px] overflow-hidden rounded-[50%]');
  const image = element('img', 'comparison-agent-icon absolute top-[50%] left-[50%] block h-[96px] w-[96px] max-w-none [filter:grayscale(1)] [transform:translate(-50%,-50%)]');
  image.src = '/agent-icon.png';
  image.alt = '';
  image.width = 96;
  image.height = 96;
  frame.appendChild(image);
  agent.append(frame, element('span', `comparison-endpoint-label whitespace-nowrap text-[10px] leading-[14px] ${protectedPath ? 'text-comparison-teal' : 'text-comparison-muted'}`, protectedPath ? 'Agents++' : 'Agent'));

  const connection = element('span', "comparison-connection relative flex min-w-0 flex-[1_1_0] items-center justify-center before:absolute before:top-[50%] before:right-0 before:left-0 before:h-px before:bg-current before:content-['']");
  const marker = protectedPath
    ? element('span', 'comparison-path-marker relative flex h-[20px] flex-[0_0_20px] items-center justify-center rounded-[50%] bg-comparison-accent text-[13px] font-bold leading-[20px] text-comparison-inset', panel.state === 'allowed' ? '✓' : panel.state === 'blocked' ? '×' : '!')
    : element('span', 'comparison-path-label relative max-w-full rounded-[999px] border border-comparison-edge bg-[#301f30] py-[2px] px-[6px] text-center text-[10px] font-semibold leading-[14px] text-comparison-red', 'No credential checks');
  connection.appendChild(marker);

  const database = element('span', 'comparison-endpoint comparison-database-endpoint flex min-w-0 flex-[0_0_60px] flex-col items-center gap-[3px]');
  const databaseIcon = icon('database');
  databaseIcon.setAttribute('class', `block h-[30px] w-[30px] p-[2px] text-[#c8d3e1] ${panel.state === 'error' || protectedPath && panel.state === 'blocked' ? 'opacity-35' : ''}`);
  database.append(databaseIcon, element('span', 'comparison-endpoint-label whitespace-nowrap text-[10px] leading-[14px] text-comparison-muted', 'Database'));
  target.setAttribute('aria-hidden', 'true');
  target.replaceChildren(agent, connection, database);
}

function renderMetrics(target, panel, prefix) {
  const tiles = panel.metrics.map((metric) => {
    const tile = element('div', 'comparison-metric flex min-h-[63px] min-w-0 flex-col items-start justify-center gap-[2px] rounded-[6px] border border-comparison-border bg-comparison-inset p-[8px]');
    tile.dataset.metric = metric.key;
    const value = element('dd', `-order-1 text-left font-pg text-[16px] font-normal leading-[22px] [overflow-wrap:anywhere] ${prefix === 'comparison-direct' && metric.key === 'rows' ? 'text-comparison-text' : 'text-comparison-accent'}`, metric.value);
    value.id = `${prefix}-${metric.key}`;
    if (metric.key === 'audit') setAuditReference(value, panel);
    tile.append(element('dt', 'font-pg text-[10px] font-normal leading-[14px] text-comparison-muted [overflow-wrap:anywhere]', metric.label), value);
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
  else target.appendChild(element('p', 'comparison-warning text-[12px] leading-[18px] text-[#f5ce8b] [overflow-wrap:anywhere]', warning));
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
  const region = element('div', 'comparison-table-scroll min-h-[265px] min-w-0 flex-auto overflow-x-auto rounded-[6px] border border-comparison-border bg-comparison-inset focus-visible:[outline:2px_solid_var(--comparison-accent)] focus-visible:outline-offset-[3px]');
  region.tabIndex = 0;
  region.setAttribute('role', 'region');
  region.setAttribute('aria-label', protectedPath ? 'Agents++ query results' : 'Direct query results');
  const table = element('table', 'comparison-table w-full border-collapse text-left text-[#e2e8f0] [border:0] [font:inherit]');
  const count = `${panel.rows.length} ${panel.rows.length === 1 ? 'row' : 'rows'}`;
  table.appendChild(element('caption', 'comparison-sr-only absolute h-px w-px overflow-hidden whitespace-nowrap [clip-path:inset(50%)]', `${protectedPath ? 'Agents++' : 'Direct'} database response: ${count}`));
  const head = element('thead');
  const headings = element('tr');
  for (const column of columns) {
    const heading = element('th', `border-b border-b-comparison-border py-[5px] px-[8px] align-top whitespace-nowrap text-[11px] font-semibold leading-[14px] uppercase ${restricted.has(column) ? 'comparison-restricted bg-[rgba(255,72,72,0.12)] text-comparison-red' : 'text-comparison-muted'}`, column);
    heading.scope = 'col';
    headings.appendChild(heading);
  }
  head.appendChild(headings);
  const body = element('tbody');
  for (const [index, row] of panel.rows.entries()) {
    const tr = element('tr');
    const border = index === panel.rows.length - 1 ? '[border-bottom:0]' : 'border-b border-b-comparison-border';
    for (const column of columns) {
      const value = Object.prototype.hasOwnProperty.call(row, column) ? row[column] : undefined;
      tr.appendChild(element('td', `py-[5px] px-[8px] align-top whitespace-nowrap text-[12px] leading-[16px] ${border} ${restricted.has(column) ? 'comparison-restricted bg-[rgba(255,72,72,0.07)] text-comparison-red' : ''}`, cellText(value)));
    }
    body.appendChild(tr);
  }
  table.append(head, body);
  region.appendChild(table);
  return region;
}

function blockedResult(notice) {
  const card = resultCard('comparison-notice items-center justify-center bg-[rgba(85,229,195,0.035)] text-center');
  const lock = icon('lock');
  lock.setAttribute('class', 'h-[16px] w-[16px] text-comparison-teal');
  card.append(
    lock,
    element('h4', 'comparison-result-title text-[13px] font-semibold leading-[20px] text-comparison-accent', notice.title),
    element('p', 'comparison-result-reason text-[12px] leading-[18px] text-comparison-muted', notice.reason),
  );
  if (notice.policy) {
    const policy = element('p', 'comparison-policy flex min-w-0 flex-wrap items-baseline justify-center gap-[6px] text-[10px] leading-[16px] text-comparison-muted');
    policy.append(element('span', '', 'Policy'), element('code', 'max-w-full whitespace-pre-wrap rounded-[4px] bg-comparison-inset py-[3px] px-[6px] text-[11px] leading-[18px] text-[#dbe6f2] [font-family:var(--playground-mono,Cousine,monospace)] [overflow-wrap:anywhere]', notice.policy));
    card.appendChild(policy);
  }
  return card;
}

function operationResult(panel, sql) {
  const card = resultCard('comparison-operation bg-comparison-tint');
  const rows = panel.metrics.find((metric) => metric.key === 'rows');
  const summary = element('p', 'comparison-operation-summary flex flex-wrap items-baseline gap-x-[12px] gap-y-[8px] text-comparison-muted');
  summary.append(element('strong', 'text-[11px] text-comparison-red', panel.command), element('span', '', rows ? `${rows.label}: ${rows.value}` : ''));
  const query = element('pre', 'comparison-operation-sql max-w-full whitespace-pre-wrap rounded-[4px] bg-comparison-inset p-[8px] text-[11px] leading-[18px] text-[#dbe6f2] [font-family:var(--playground-mono,Cousine,monospace)] [overflow-wrap:anywhere]');
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
  return element('div', `${className} flex min-h-[265px] min-w-0 flex-auto flex-col gap-[12px] rounded-[6px] border border-comparison-edge p-[16px] [overflow-wrap:anywhere]`);
}

function renderResult(target, panel, protectedPath, sql) {
  let content;
  if (panel.state === 'error') {
    content = resultCard('comparison-error bg-comparison-tint');
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
