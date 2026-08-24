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
  version: 1 | 2 | 3;
  status?: 'success' | 'rejected';
  reason?: string;
  reasonCode?: string;
  /** Supplied by the authenticated transport or query context when organizational attribution applies. */
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
