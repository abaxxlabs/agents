/**
 * Structured decision trace and evidence for Playground query results.
 * Rendered by the UI under "Technical details"; never fabricated client-side.
 */

export function allowedQueryInspection(agent, sql, metadata) {
  return {
    decisionTrace: [
      'Credential accepted',
      'Agent matched',
      'Action: read',
      'Projection within scope',
      'Query executed',
      'Audit recorded',
    ],
    evidence: {
      agent,
      sql,
      authorization: 'allowed',
      columnsDecrypted: metadata?.columnsDecrypted ?? [],
      auditId: metadata?.auditId ?? null,
    },
  };
}

export function rejectedQueryInspection(agent, sql, err) {
  const candidateAuditId = err.details?.auditId;
  const auditId = typeof candidateAuditId === 'string' && candidateAuditId.trim()
    ? candidateAuditId
    : null;
  const auditTrace = auditId ? 'Rejection recorded' : 'Rejection audit not confirmed';
  return {
    decisionTrace: err.code === 'SCOPE_VIOLATION'
      ? [
          'Credential accepted',
          err.message,
          'Query not executed',
          auditTrace,
        ]
      : ['Request rejected', 'Query not executed', auditTrace],
    evidence: {
      agent,
      sql,
      authorization: 'rejected',
      error: err.code ?? err.constructor?.name ?? 'Error',
      auditId,
    },
  };
}
