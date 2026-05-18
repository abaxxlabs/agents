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

/**
 * CLI: agents verify <audit-file>
 *
 * Verify an exported audit trail:
 * 1. Read JSON audit records from file or database
 * 2. For each record, resolve the agent DID → public key
 * 3. Verify the JWS signature
 * 4. Report pass/fail for each record
 */

import { readFileSync } from 'node:fs';
import pg from 'pg';
import type { AuditRecord } from '../types.js';
import { VcVerifier } from '../vc-verifier.js';
import { InMemoryRevocationStore } from '../storage/memory/revocation-store.js';
import { AuditLogger } from '../audit-logger.js';
import { PostgresAuditStore } from '../storage/postgres/audit-store.js';
import type { AuditStore } from '../storage/types.js';

const { Pool } = pg;

/**
 * No-op AuditStore for offline signature verification.
 * verifyRecord() doesn't touch the store — it only needs the AuditLogger
 * instance for the verifyJwtSignature wrapper. All store methods throw
 * because they should never be called in the offline path.
 */
const NOOP_AUDIT_STORE: AuditStore = {
  append: () => {
    throw new Error('not available in offline verify mode');
  },
  loadLastRecord: () => {
    throw new Error('not available in offline verify mode');
  },
  loadLastRecordLocked: () => {
    throw new Error('not available in offline verify mode');
  },
  query: () => {
    throw new Error('not available in offline verify mode');
  },
  count: () => {
    throw new Error('not available in offline verify mode');
  },
};

export interface VerifyOptions {
  db?: string;
  agent?: string;
  since?: string;
  json?: boolean;
}

export async function runVerify(auditFileOrDb: string, options: VerifyOptions): Promise<void> {
  let records: AuditRecord[];

  // Determine if input is a file or database connection string
  if (auditFileOrDb.startsWith('postgresql://') || auditFileOrDb.startsWith('postgres://')) {
    records = await loadFromDatabase(auditFileOrDb, options);
  } else {
    records = loadFromFile(auditFileOrDb);
  }

  if (records.length === 0) {
    console.log('\n[agents] No audit records to verify.\n');
    return;
  }

  console.log(`\n[agents] Verifying ${records.length} audit record(s)...\n`);

  const verifier = new VcVerifier({
    clockSkew: '5s',
    revocationStore: new InMemoryRevocationStore(),
  });
  let passed = 0;
  let failed = 0;
  const results: Array<{ id: string; agent: string; valid: boolean; error?: string }> = [];

  for (const record of records) {
    try {
      // Resolve agent's public key from DID
      const publicKey = await verifier.resolvePublicKey(record.agentDid);
      const logger = new AuditLogger({ auditStore: NOOP_AUDIT_STORE, enabled: false });
      const valid = await logger.verifyRecord(record, publicKey);

      if (valid) {
        passed++;
        if (!options.json) {
          console.log(
            `  ✓ ${record.id}  agent=${record.agentDid.slice(0, 24)}...  ${record.timestamp}`,
          );
        }
      } else {
        failed++;
        if (!options.json) {
          console.log(
            `  ✗ ${record.id}  INVALID SIGNATURE  agent=${record.agentDid.slice(0, 24)}...`,
          );
        }
      }

      results.push({ id: record.id, agent: record.agentDid, valid });
    } catch (err) {
      failed++;
      const error = err instanceof Error ? err.message : String(err);
      if (!options.json) {
        console.log(`  ✗ ${record.id}  ERROR: ${error}`);
      }
      results.push({ id: record.id, agent: record.agentDid, valid: false, error });
    }
  }

  if (options.json) {
    console.log(JSON.stringify({ total: records.length, passed, failed, results }, null, 2));
  } else {
    console.log(
      `\n[agents] Results: ${passed} passed, ${failed} failed (${records.length} total)\n`,
    );
    if (failed > 0) {
      process.exitCode = 1;
    }
  }
}

function loadFromFile(path: string): AuditRecord[] {
  try {
    const content = readFileSync(path, 'utf-8');
    const parsed = JSON.parse(content);
    // Accept either an array or { records: [...] }
    return Array.isArray(parsed) ? parsed : (parsed.records ?? []);
  } catch (err) {
    console.error(`[agents] Cannot read audit file: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

async function loadFromDatabase(
  connectionString: string,
  options: VerifyOptions,
): Promise<AuditRecord[]> {
  const pool = new Pool({ connectionString });

  try {
    await pool.query('SELECT 1');
  } catch (err) {
    console.error(`[agents] Cannot connect: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  const logger = new AuditLogger({ auditStore: new PostgresAuditStore(pool), enabled: true });
  const filter: { agentDid?: string; since?: Date } = {};

  if (options.agent) filter.agentDid = options.agent;
  if (options.since) filter.since = new Date(options.since);

  const records = await logger.export(filter);
  await pool.end();
  return records;
}
