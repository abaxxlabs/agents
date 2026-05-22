export interface AuditRecord {
  id: string;
  timestamp: string;
  agentDid: string;
  ownerDid: string;
  credentialId: string;
  queryHash: string;
  columnsAccessed: string[];
  rowCount: number;
  durationMs: number;
  previousHash: string;
  signature: string;
  version: 1 | 2 | 3;
  status?: 'success' | 'rejected';
  reason?: string;
  reasonCode?: string;
  /** Derived from the verified credential's issuer -- never from caller input. */
  orgId?: string;
}

export interface AuditEntry {
  agentDid: string;
  ownerDid: string;
  credentialJwt: string;
  sql: string;
  columnsAccessed: string[];
  rowCount: number;
  durationMs: number;
  orgId?: string;
}
