const MUTATIONS = new Set(['DELETE', 'UPDATE']);

function metric(key, value, label) {
  return { key, value, label };
}

function message(body) {
  return body?.message || body?.error || 'The request could not be completed.';
}

function hasPlainProjection(sql, fields, knownColumns) {
  const match = /^\s*SELECT\s+([a-z0-9_.,\s]+)\s+FROM\s+orders\s*;?\s*$/i.exec(sql);
  if (!match) return false;
  const names = match[1].split(',').map((name) => name.trim().toLowerCase().replace(/^orders\./, ''));
  return names.length === fields.length && names.every((name, index) =>
    knownColumns.includes(name) && name === fields[index]);
}

export function createComparisonModel({ request, direct, protectedPath, auditRecords = [] }) {
  const raw = direct.body ?? {};
  const scoped = protectedPath.body ?? {};
  const directOk = direct.status === 200 && raw.ok === true;
  const allowed = protectedPath.status === 200 && scoped.ok === true;
  const blocked = protectedPath.status === 403;
  const code = scoped.inspection?.evidence?.error;
  const command = raw.command ?? null;
  const mutation = MUTATIONS.has(command);
  const kind = allowed ? 'allowed'
    : blocked && code === 'SCOPE_VIOLATION' ? 'scope-blocked'
      : blocked && code === 'QUERY_REJECTED' && mutation ? 'write-blocked' : 'error';
  const columns = request.columns.map((column) => column.replace(/^orders\./, ''));
  const rawRows = directOk && command === 'SELECT' && Array.isArray(raw.rows) ? raw.rows : [];
  const scopedRows = allowed && Array.isArray(scoped.rows) ? scoped.rows : [];
  const fieldNames = Object.keys(rawRows[0] ?? {});
  const knownProjection = !rawRows.length || hasPlainProjection(request.sql, fieldNames, request.knownColumns);
  const restrictedColumns = kind === 'scope-blocked' && knownProjection
    ? fieldNames.filter((name) => request.knownColumns.includes(name) && !columns.includes(name)) : [];
  const exposed = knownProjection
    ? rawRows.reduce((count, row) => count + restrictedColumns.filter((name) => row[name] != null).length, 0)
    : 'Not available';
  const candidateId = allowed ? scoped.metadata?.auditId : blocked ? scoped.inspection?.evidence?.auditId : null;
  const auditId = typeof candidateId === 'string' && candidateId.trim() ? candidateId : null;
  const auditConfirmed = Boolean(auditId && (allowed || blocked) && auditRecords.some((record) =>
    record.id === auditId && record.agentDid === request.agent &&
    record.status === (allowed ? 'success' : 'rejected')));
  const rowLabel = command === 'DELETE' ? 'Rows deleted' : command === 'UPDATE' ? 'Rows updated' : 'Rows returned';
  const directCount = directOk ? mutation ? raw.rowCount ?? 'Not available' : rawRows.length : '—';
  const scopedCount = allowed ? scopedRows.length : blocked ? 0 : '—';
  const directMetrics = [metric('rows', directCount, rowLabel)];
  const scopedMetrics = [metric('rows', scopedCount, rowLabel)];
  if (kind === 'scope-blocked') {
    directMetrics.push(metric('exposed', directOk ? exposed : '—', 'Restricted values exposed'));
    scopedMetrics.push(metric('exposed', 0, 'Restricted values exposed'));
  } else {
    const label = mutation ? 'Permission check' : 'Policy check';
    directMetrics.push(metric('policy', 'None', label));
    scopedMetrics.push(metric('policy', allowed ? 'Passed' : blocked ? 'Failed' : 'Not confirmed', label));
  }
  directMetrics.push(metric('audit', 'None', 'Agents++ audit record'));
  scopedMetrics.push(metric('audit', auditConfirmed ? 'Saved' : 'Not confirmed', 'Audit record'));

  let notice = null;
  if (!allowed) {
    const reason = kind === 'scope-blocked'
      ? restrictedColumns.length
        ? `${restrictedColumns.join(', ')} are outside this agent's credential scope, so the whole query was refused.`
        : 'The query references columns outside the issued credential scope, so no protected rows were returned.'
      : kind === 'write-blocked'
        ? `This agent can only read. ${command} is not allowed by the SELECT-only policy.`
        : message(scoped);
    notice = {
      title: blocked ? 'Blocked before the business query' : 'Request could not be completed',
      reason,
      policy: kind === 'scope-blocked' ? `read: ${columns.join(', ')}`
        : kind === 'write-blocked' ? 'allowed operations: SELECT' : '',
    };
  }

  const operation = directOk && mutation ? {
    title: typeof raw.rowCount === 'number'
      ? `${raw.rowCount} ${raw.rowCount === 1 ? 'row' : 'rows'} ${command === 'DELETE' ? 'deleted from' : 'updated in'} the demo sandbox`
      : 'Operation executed in the demo sandbox',
    description: 'The direct path executed this operation without checking an Agents++ credential. Sandbox data resets before each comparison.',
  } : null;
  const directStatus = !directOk ? 'Request rejected'
    : mutation ? `Executed · ${command === 'DELETE' ? 'rows deleted' : 'rows updated'}`
      : kind === 'scope-blocked' && typeof exposed === 'number' && exposed > 0
        ? 'Executed · data exposed' : 'Executed · unchecked';
  return {
    kind,
    sql: request.sql,
    direct: {
      state: directOk ? 'executed' : 'error',
      status: directStatus,
      command,
      metrics: directMetrics,
      rows: rawRows,
      restrictedColumns,
      notice: null,
      operation,
      error: directOk ? null : message(raw),
      warning: raw.limitedBy ? 'The sandbox response reached its result limit; only the returned rows are shown.' : null,
      auditId: null,
      auditConfirmed: false,
    },
    scoped: {
      state: allowed ? 'allowed' : blocked ? 'blocked' : 'error',
      status: allowed ? '✓ Allowed' : blocked ? '× Blocked' : 'Request failed',
      command,
      metrics: scopedMetrics,
      rows: scopedRows,
      restrictedColumns: [],
      notice,
      operation: null,
      error: !allowed && !blocked ? message(scoped) : null,
      warning: !auditConfirmed ? 'Audit persistence has not been confirmed for this request.' : null,
      auditId,
      auditConfirmed,
    },
  };
}
