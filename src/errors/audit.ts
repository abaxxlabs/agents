import { AgentScopeError } from './base.js';

export class AuditWriteFailedError extends AgentScopeError {
  constructor(reason: string) {
    super(
      'AUDIT_WRITE_FAILED',
      `Could not write audit record — ${reason}. Query blocked.`,
      { reason },
    );
    this.name = 'AuditWriteFailedError';
  }
}
