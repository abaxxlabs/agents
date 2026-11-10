// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
  version: 1 | 2 | 3 | 4 | 5;
  status?: 'success' | 'rejected';
  reason?: string;
  reasonCode?: string;
  /** Supplied by the authenticated transport or query context when organizational attribution applies. */
  orgId?: string;
  /** Delegating agent DID for a delegated query (the credential's issuer). Absent for direct queries. */
  delegatorDid?: string;
  /** JTI of the source credential the delegation was granted from. Absent for direct queries. */
  delegatedGrantId?: string;
  /** What the record describes. Absent on records written before version 5, which are queries. */
  eventKind?: AuditEventKind;
  /** Message records only: whether this agent sent or received it. */
  direction?: MessageDirection;
  /**
   * Message records only: the peer agent. Verified on a delivered or accepted message. On a
   * refused send it is the recipient as requested. Absent on a refused receipt.
   */
  counterpartAgentDid?: string;
  /** Message records only: the server DID of the peer's instance, once verified. */
  counterpartInstanceDid?: string;
  /** Message records only: the DWN record id of the message. */
  messageRecordId?: string;
  /** Message records only: SHA-256 of the sealed ciphertext, hex. Never the text. */
  messageDigest?: string;
}

export type AuditEventKind = 'query' | 'message';
export type MessageDirection = 'sent' | 'received';

/** One agent-to-agent message event, recorded on the acting agent's instance. */
export interface MessageAuditEvent {
  agentDid: string;
  ownerDid: string;
  direction: MessageDirection;
  status: 'success' | 'rejected';
  messageRecordId: string;
  /** SHA-256 of the sealed ciphertext, hex. Absent when nothing was sealed (a refused send). */
  messageDigest?: string;
  counterpartAgentDid?: string;
  counterpartInstanceDid?: string;
  /** Rejections only. */
  reason?: string;
  reasonCode?: string;
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
  delegatorDid?: string;
  delegatedGrantId?: string;
}
