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

import type { AuditLogger } from '#audit/index.js';
import type { RegisteredAgent } from '#types/auth.js';
import type { ScopedResult } from './types.js';
import { CredentialInvalidError } from '#errors/index.js';

export interface ResultAssemblerOptions {
  auditLogger: AuditLogger;
  agents: Map<string, RegisteredAgent>;
}

export interface ResultAssemblyInput {
  agent: string;
  ownerDid: string;
  credentialJwt: string;
  sql: string;
  columnsAccessed: string[];
  rowCount: number;
  durationMs: number;
  orgId?: string;
  decryptedRows: Record<string, unknown>[];
  columnsDecrypted: string[];
  columnsEncrypted: string[];
}

/**
 * Writes the audit record and assembles the ScopedResult metadata.
 */
export class ResultAssembler {
  private auditLogger: AuditLogger;
  private agents: Map<string, RegisteredAgent>;

  constructor(options: ResultAssemblerOptions) {
    this.auditLogger = options.auditLogger;
    this.agents = options.agents;
  }

  async assemble(input: ResultAssemblyInput): Promise<ScopedResult> {
    // Fail closed — the agent must be registered to proceed (no silent audit skip).
    const auditAgent = this.agents.get(input.agent);
    if (!auditAgent) {
      throw new CredentialInvalidError(
        input.agent,
        `Agent ${input.agent} is not registered. Cannot create signed audit record.`,
      );
    }

    const auditRecord = await this.auditLogger.log(
      {
        agentDid: input.agent,
        ownerDid: input.ownerDid,
        credentialJwt: input.credentialJwt,
        sql: input.sql,
        columnsAccessed: input.columnsAccessed,
        rowCount: input.rowCount,
        durationMs: input.durationMs,
        orgId: input.orgId,
      },
      auditAgent.signer,
    );

    return {
      rows: input.decryptedRows,
      metadata: {
        agent: input.agent,
        owner: input.ownerDid,
        columnsDecrypted: input.columnsDecrypted,
        columnsEncrypted: input.columnsEncrypted,
        rowCount: input.rowCount,
        queryDurationMs: input.durationMs,
        auditId: auditRecord.id,
      },
    };
  }
}
