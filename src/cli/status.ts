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
 * CLI: agents status
 *
 * Show agents middleware status:
 * - Database connection health
 * - Encrypted columns and key status
 * - Registered agents
 * - Recent audit activity
 * - Abaxx One connectivity
 */

import pg from 'pg';
import { loadConfig } from '../config.js';

const { Pool } = pg;

export interface StatusOptions {
  db?: string;
  config?: string;
  abaxxOne?: string;
  json?: boolean;
}

interface StatusReport {
  database: { connected: boolean; version?: string; error?: string };
  tables: { name: string; exists: boolean; rowCount?: number }[];
  encryptedColumns: { table: string; column: string; algorithm: string; createdAt: string }[];
  agents: { did: string; name: string; ownerDid: string; createdAt: string }[];
  auditSummary: { totalRecords: number; recentRecords: number; lastActivity?: string };
  abaxxOne: { reachable: boolean; issuer?: string; error?: string };
}

export async function runStatus(options: StatusOptions): Promise<void> {
  let connectionString = options.db;
  let abaxxOneUrl = options.abaxxOne;

  if (!connectionString && options.config) {
    try {
      const config = loadConfig(options.config);
      connectionString = config.database.connectionString;
      abaxxOneUrl = abaxxOneUrl ?? config.abaxxOne?.tenantUrl ?? config.oidc?.issuerUrl;
    } catch {
      // Config file not found — fall through to error
    }
  }

  if (!connectionString) {
    console.error('[agents] No database connection. Use --db <url> or --config <path>.');
    process.exit(1);
  }

  const report: StatusReport = {
    database: { connected: false },
    tables: [],
    encryptedColumns: [],
    agents: [],
    auditSummary: { totalRecords: 0, recentRecords: 0 },
    abaxxOne: { reachable: false },
  };

  const pool = new Pool({ connectionString });
  try {
    const versionRes = await pool.query('SELECT version()');
    report.database = {
      connected: true,
      version: versionRes.rows[0].version.split(',')[0],
    };
  } catch (err) {
    report.database = {
      connected: false,
      error: err instanceof Error ? err.message : String(err),
    };
    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log('\n[agents] Status\n');
      console.log(`  Database: ✗ ${report.database.error}`);
    }
    await pool.end();
    return;
  }

  const requiredTables = ['agents', 'agent_keys', 'agent_columns', 'agent_audit'];
  for (const tableName of requiredTables) {
    try {
      const res = await pool.query(`SELECT COUNT(*)::int as count FROM ${tableName}`);
      report.tables.push({ name: tableName, exists: true, rowCount: res.rows[0].count });
    } catch {
      report.tables.push({ name: tableName, exists: false });
    }
  }

  try {
    const keysRes = await pool.query(
      'SELECT table_name, column_name, algorithm, created_at FROM agent_keys ORDER BY created_at',
    );
    report.encryptedColumns = keysRes.rows.map((r) => ({
      table: r.table_name,
      column: r.column_name,
      algorithm: r.algorithm,
      createdAt: r.created_at,
    }));
  } catch {
    // Table doesn't exist
  }

  try {
    const agentsRes = await pool.query(
      'SELECT did, name, owner_did, created_at FROM agents ORDER BY created_at DESC LIMIT 20',
    );
    report.agents = agentsRes.rows.map((r) => ({
      did: r.did,
      name: r.name,
      ownerDid: r.owner_did,
      createdAt: r.created_at,
    }));
  } catch {
    // Table doesn't exist
  }

  try {
    const totalRes = await pool.query('SELECT COUNT(*)::int as count FROM agent_audit');
    const recentRes = await pool.query(
      "SELECT COUNT(*)::int as count FROM agent_audit WHERE timestamp > NOW() - INTERVAL '24 hours'",
    );
    const lastRes = await pool.query(
      'SELECT timestamp FROM agent_audit ORDER BY timestamp DESC LIMIT 1',
    );

    report.auditSummary = {
      totalRecords: totalRes.rows[0].count,
      recentRecords: recentRes.rows[0].count,
      lastActivity: lastRes.rows[0]?.timestamp,
    };
  } catch {
    // Table doesn't exist
  }

  if (abaxxOneUrl) {
    try {
      const res = await fetch(`${abaxxOneUrl}/.well-known/openid_configuration`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const config = (await res.json()) as { issuer?: string };
        report.abaxxOne = { reachable: true, issuer: config.issuer };
      } else {
        report.abaxxOne = { reachable: false, error: `HTTP ${res.status}` };
      }
    } catch (err) {
      report.abaxxOne = {
        reachable: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  await pool.end();

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  printStatus(report, abaxxOneUrl);
}

function printStatus(report: StatusReport, abaxxOneUrl?: string): void {
  console.log('\n[agents] Status\n');

  const dbIcon = report.database.connected ? '✓' : '✗';
  console.log(`  Database: ${dbIcon} ${report.database.version ?? report.database.error}`);

  const allExist = report.tables.every((t) => t.exists);
  if (allExist) {
    console.log('  Tables:   ✓ All agents infrastructure tables present');
  } else {
    const missing = report.tables.filter((t) => !t.exists).map((t) => t.name);
    console.log(`  Tables:   ✗ Missing: ${missing.join(', ')}`);
    console.log('            Run: npx agents init --db <url>');
  }

  if (report.encryptedColumns.length > 0) {
    console.log(`  Columns:  ${report.encryptedColumns.length} encrypted`);
    for (const col of report.encryptedColumns) {
      console.log(`            • ${col.table}.${col.column} (${col.algorithm})`);
    }
  } else {
    console.log('  Columns:  0 encrypted');
  }

  console.log(`  Agents:   ${report.agents.length} registered`);
  for (const agent of report.agents.slice(0, 5)) {
    console.log(`            • ${agent.name} (${agent.did.slice(0, 24)}...)`);
  }
  if (report.agents.length > 5) {
    console.log(`            ... and ${report.agents.length - 5} more`);
  }

  console.log(
    `  Audit:    ${report.auditSummary.totalRecords} records (${report.auditSummary.recentRecords} in last 24h)`,
  );
  if (report.auditSummary.lastActivity) {
    console.log(`            Last: ${report.auditSummary.lastActivity}`);
  }

  if (abaxxOneUrl) {
    const oneIcon = report.abaxxOne.reachable ? '✓' : '✗';
    const oneDetail = report.abaxxOne.reachable
      ? `${abaxxOneUrl} (issuer: ${report.abaxxOne.issuer})`
      : `${abaxxOneUrl} (${report.abaxxOne.error})`;
    console.log(`  Abaxx One: ${oneIcon} ${oneDetail}`);
  }

  console.log('');
}
