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

// Demo runner — mock auth requires development mode
if (!process.env.NODE_ENV) process.env.NODE_ENV = 'development';

/**
 * Agents++ — Demo Runner
 *
 * The 90-second killer demo:
 * 1. Connect to Postgres (with pre-encrypted sample data)
 * 2. Authenticate a demo human
 * 3. Create Agent A (full scope) and Agent B (name only)
 * 4. Issue scoped credentials to both
 * 5. Both agents query the same table
 * 6. Print side-by-side comparison showing Agent A sees cleartext, Agent B sees ciphertext
 * 7. Print audit trail with both agents' signed records
 */

import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { AgentScope } from '#sql/index.js';
import { encrypt, generateColumnKey, wrapColumnKey } from '#encryption/index.js';
import { parseMasterKeyHex } from '#bootstrap/index.js';

const { Pool } = pg;

interface DemoOptions {
  db: string;
}

export async function runDemo(options: DemoOptions): Promise<void> {
  const masterKeyHex = process.env.AGENTS_MASTER_KEY ?? randomBytes(32).toString('hex');

  console.log('\n' + '═'.repeat(70));
  console.log('  Agents++ — Demo');
  console.log('  Encryption-based identity and access control for AI agents');
  console.log('═'.repeat(70));
  console.log('');
  console.log('  TOOLING');
  console.log('  ─────────────────────────────────────────────────────────');
  console.log('  Identity:    did:key (Ed25519) — self-resolving DIDs');
  console.log('  Credentials: Verifiable Credentials (W3C) as signed JWTs');
  console.log('  Encryption:  AES-256-GCM per-column, application-layer');
  console.log('  Signing:     Ed25519 (EdDSA) for credentials + audit');
  console.log('  Database:    PostgreSQL — encrypted columns stored as bytea');
  console.log('  Auth:        Abaxx One (OAuth 2.0 + PKCE) — mock for demo');
  console.log('  Runtime:     Node.js, TypeScript, node:crypto (no native deps)');
  console.log('  Package:     @abaxxlabs/agents (ESM + CJS dual build)');
  console.log('');
  console.log('  HOW IT WORKS');
  console.log('  ─────────────────────────────────────────────────────────');
  console.log('  1. A human authenticates and creates AI agents (each gets a DID)');
  console.log('  2. The human issues scoped credentials specifying which columns');
  console.log("     each agent can see — signed with the human's Ed25519 key");
  console.log('  3. When an agent queries, the middleware:');
  console.log('     a) Verifies the credential signature and expiry');
  console.log("     b) Confirms the credential issuer is the agent's owner");
  console.log('     c) Decrypts only the columns the credential authorizes');
  console.log('     d) Returns everything else as base64 ciphertext');
  console.log("     e) Signs an audit record with the agent's private key");
  console.log('  4. No key? No cleartext. The encryption IS the access control.');
  console.log('');

  // ─── Step 0: Setup database ──────────────────────────────────

  console.log('📋 Setting up demo database...\n');

  const pool = new Pool({ connectionString: options.db });

  try {
    await pool.query('SELECT 1');
  } catch {
    console.error(`❌ Cannot connect to PostgreSQL at ${options.db}`);
    console.error('   Run "docker compose up" in the demo/ directory first.');
    process.exit(1);
  }

  // Clean slate for each demo run — drop and recreate to pick up schema changes
  await pool.query('DROP TABLE IF EXISTS patients CASCADE');
  await pool.query('DROP TABLE IF EXISTS agent_audit CASCADE');
  await pool.query('DROP TABLE IF EXISTS agent_columns CASCADE');
  await pool.query('DROP TABLE IF EXISTS agents CASCADE');
  await pool.query('DROP TABLE IF EXISTS agent_keys CASCADE');

  // Create schema
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agents (
      did TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_did TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_keys (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      table_name TEXT NOT NULL,
      column_name TEXT NOT NULL,
      encrypted_key BYTEA NOT NULL,
      algorithm TEXT DEFAULT 'aes-256-gcm',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      rotated_at TIMESTAMPTZ,
      UNIQUE(table_name, column_name)
    );

    CREATE TABLE IF NOT EXISTS agent_columns (
      table_name TEXT NOT NULL,
      column_name TEXT NOT NULL,
      key_id UUID REFERENCES agent_keys(id),
      original_type TEXT NOT NULL,
      is_encrypted BOOLEAN DEFAULT false,
      PRIMARY KEY (table_name, column_name)
    );

    CREATE TABLE IF NOT EXISTS agent_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      timestamp TIMESTAMPTZ DEFAULT NOW(),
      agent_did TEXT NOT NULL,
      owner_did TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      query_hash TEXT NOT NULL,
      columns_accessed JSONB NOT NULL,
      row_count INTEGER NOT NULL,
      duration_ms INTEGER NOT NULL,
      previous_hash TEXT NOT NULL DEFAULT 'GENESIS',
      signature TEXT NOT NULL
    );

    -- Append-only enforcement
    CREATE OR REPLACE FUNCTION agent_audit_immutable()
    RETURNS TRIGGER AS $$
    BEGIN
      RAISE EXCEPTION 'agent_audit is append-only: % not allowed', TG_OP;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_audit_immutable ON agent_audit;
    CREATE TRIGGER trg_audit_immutable
      BEFORE UPDATE OR DELETE ON agent_audit
      FOR EACH ROW EXECUTE FUNCTION agent_audit_immutable();

    CREATE OR REPLACE FUNCTION agent_audit_no_truncate()
    RETURNS TRIGGER AS $$
    BEGIN
      RAISE EXCEPTION 'agent_audit is append-only: TRUNCATE not allowed';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_audit_no_truncate ON agent_audit;
    CREATE TRIGGER trg_audit_no_truncate
      BEFORE TRUNCATE ON agent_audit
      FOR EACH STATEMENT EXECUTE FUNCTION agent_audit_no_truncate();
  `);

  let masterKey;
  try {
    masterKey = parseMasterKeyHex(masterKeyHex);
  } catch (err) {
    console.error(`[agents] ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  await pool.query(`
    CREATE TABLE patients (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      dob BYTEA,
      diagnosis BYTEA,
      ssn BYTEA
    )
  `);

  // Generate column keys and register them
  const columns = ['patients.dob', 'patients.diagnosis', 'patients.ssn'];
  const columnKeys = new Map<string, Buffer>();

  for (const col of columns) {
    const [table, column] = col.split('.');
    const key = generateColumnKey();
    const wrapped = wrapColumnKey(key, masterKey);
    columnKeys.set(col, key);

    await pool.query(
      `INSERT INTO agent_keys (table_name, column_name, encrypted_key, algorithm)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (table_name, column_name) DO UPDATE SET encrypted_key = $3`,
      [table, column, wrapped, 'aes-256-gcm'],
    );
  }

  // Insert sample patients with encrypted values
  const patients = [
    { name: 'Jane Doe', dob: '1990-03-15', diagnosis: 'Type 2 Diabetes', ssn: '123-45-6789' },
    { name: 'John Smith', dob: '1985-07-22', diagnosis: 'Hypertension', ssn: '987-65-4321' },
    { name: 'Alice Wong', dob: '1978-11-03', diagnosis: 'Asthma', ssn: '456-78-9012' },
    { name: 'Bob Johnson', dob: '1992-01-30', diagnosis: 'Anxiety Disorder', ssn: '321-54-9876' },
    { name: 'Maria Garcia', dob: '1988-06-17', diagnosis: 'Migraine', ssn: '654-32-1098' },
  ];

  for (const p of patients) {
    const encDob = encrypt(p.dob, columnKeys.get('patients.dob')!);
    const encDiag = encrypt(p.diagnosis, columnKeys.get('patients.diagnosis')!);
    const encSsn = encrypt(p.ssn, columnKeys.get('patients.ssn')!);

    await pool.query('INSERT INTO patients (name, dob, diagnosis, ssn) VALUES ($1, $2, $3, $4)', [
      p.name,
      encDob,
      encDiag,
      encSsn,
    ]);
  }

  console.log(`   ✅ Created patients table with ${patients.length} rows`);
  console.log(`   ✅ Encrypted columns: dob, diagnosis, ssn (AES-256-GCM, per-column keys)`);
  console.log(`   ✅ Cleartext column: name (no encryption — visible to all agents)`);
  console.log(`   ✅ Each column key is wrapped (encrypted) by the master key before storage\n`);

  await pool.end();

  const scope = await AgentScope.create(
    {
      database: { connectionString: options.db },
      abaxxOne: { tenantUrl: 'http://localhost:3001', clientId: 'demo' },
      encryption: { columns },
      audit: { enabled: true },
    },
    { masterKey },
  );

  console.log('🔐 Middleware initialized');
  console.log('   Column keys loaded from DB and unwrapped with master key (in memory only)\n');

  // ─── Step 2: Authenticate human ──────────────────────────────

  const session = await scope.authenticate({ mockHumanDid: 'Dr. Sarah Chen' });
  console.log(`👤 Human authenticated: ${session.humanDid}`);
  console.log(`   Email: ${session.email}`);
  console.log('   (Production: OAuth 2.0 + PKCE via Abaxx One — mock for demo)\n');

  // ─── Step 3: Create agents ───────────────────────────────────

  const agentA = await scope.createAgent({ name: 'claims-processor', ownerDid: session.humanDid });
  const agentB = await scope.createAgent({ name: 'scheduling-bot', ownerDid: session.humanDid });

  console.log(`🤖 Agent A (claims-processor): ${agentA.did}`);
  console.log(`🤖 Agent B (scheduling-bot):   ${agentB.did}`);
  console.log('   Each agent has a unique did:key DID (Ed25519 keypair)');
  console.log('   Private keys are held in opaque signers — never exposed as raw bytes\n');

  // ─── Step 4: Issue credentials ───────────────────────────────

  const credA = await session.issueCredential({
    agent: agentA.did,
    columns: ['patients.name', 'patients.dob', 'patients.diagnosis'],
    actions: ['read'],
    expiresIn: '4h',
  });

  const credB = await session.issueCredential({
    agent: agentB.did,
    columns: ['patients.name'],
    actions: ['read'],
    expiresIn: '4h',
  });

  console.log('📜 Credentials issued (W3C Verifiable Credentials as JWT):');
  console.log('   Agent A scope: name, dob, diagnosis (full clinical access)');
  console.log('   Agent B scope: name only (scheduling — no PHI)');
  console.log("   Both signed by Dr. Chen's Ed25519 key, expire in 4 hours");
  console.log('   Credential = proof of what data an agent is allowed to decrypt\n');

  // ─── Step 5: Query — Agent A (full scope) ────────────────────

  console.log('─'.repeat(70));
  console.log('  AGENT A QUERY: SELECT * FROM patients LIMIT 3');
  console.log('  Pipeline: verify JWT → check issuer → SELECT guard → decrypt → audit');
  console.log('─'.repeat(70) + '\n');

  const resultA = await scope.query({
    agent: agentA.did,
    credential: credA,
    table: 'patients',
    sql: 'SELECT name, dob, diagnosis, ssn FROM patients LIMIT 3',
  });

  console.log('  Agent A sees:\n');
  printResultTable(resultA.rows);
  console.log(`\n  Decrypted: ${resultA.metadata.columnsDecrypted.join(', ')}`);
  console.log(`  Ciphertext: ${resultA.metadata.columnsEncrypted.join(', ')}`);
  console.log(`  Audit ID: ${resultA.metadata.auditId}\n`);

  // ─── Step 6: Query — Agent B (narrow scope) ──────────────────

  console.log('─'.repeat(70));
  console.log('  AGENT B QUERY: SELECT * FROM patients LIMIT 3');
  console.log('  Pipeline: verify JWT → check issuer → SELECT guard → decrypt → audit');
  console.log('  Same pipeline, same table — but credential only authorizes "name"');
  console.log('─'.repeat(70) + '\n');

  const resultB = await scope.query({
    agent: agentB.did,
    credential: credB,
    table: 'patients',
    sql: 'SELECT name, dob, diagnosis, ssn FROM patients LIMIT 3',
  });

  console.log('  Agent B sees:\n');
  printResultTable(resultB.rows);
  console.log(
    `\n  Decrypted: ${resultB.metadata.columnsDecrypted.join(', ') || '(none beyond name)'}`,
  );
  console.log(`  Ciphertext: ${resultB.metadata.columnsEncrypted.join(', ')}`);
  console.log(`  Audit ID: ${resultB.metadata.auditId}\n`);

  // ─── Step 7: Show audit trail ────────────────────────────────

  console.log('─'.repeat(70));
  console.log('  AUDIT TRAIL (hash-chained, append-only)');
  console.log("  Each record is Ed25519-signed by the agent's private key (EdDSA)");
  console.log('  Records are hash-chained: each includes SHA-256 of the previous');
  console.log('  DB trigger prevents UPDATE/DELETE — append-only at the database level');
  console.log("  Verification uses the agent's public key from its did:key DID");
  console.log('─'.repeat(70) + '\n');

  const auditRecords = await scope.auditLoggerInstance.export({});

  // Show hash chain
  console.log('  HASH CHAIN: GENESIS');
  for (let i = 0; i < auditRecords.length; i++) {
    const record = auditRecords[i];
    const agentName = record.agentDid === agentA.did ? 'claims-processor' : 'scheduling-bot';
    const prevDisplay =
      record.previousHash === 'GENESIS' ? 'GENESIS' : record.previousHash.slice(0, 16) + '...';
    console.log(`    → [${agentName}] prev: ${prevDisplay}`);
  }
  console.log('');

  for (const record of auditRecords) {
    const agentName = record.agentDid === agentA.did ? 'claims-processor' : 'scheduling-bot';
    console.log(`  📝 Agent: ${agentName}`);
    console.log(`     DID: ${record.agentDid.slice(0, 30)}...`);
    console.log(`     Owner: ${record.ownerDid.slice(0, 30)}...`);
    console.log(`     Columns: ${record.columnsAccessed.join(', ')}`);
    console.log(`     Rows: ${record.rowCount} | Duration: ${record.durationMs}ms`);
    console.log(
      `     Hash chain: ${record.previousHash === 'GENESIS' ? 'GENESIS (first record)' : record.previousHash.slice(0, 24) + '...'}`,
    );
    console.log(`     Signature: ${record.signature.slice(0, 40)}...`);

    // Verify
    const agent = record.agentDid === agentA.did ? agentA : agentB;
    const verified = await scope.auditLoggerInstance.verifyRecord(record, agent.publicKey);
    console.log(`     Verified: ${verified ? '✅' : '❌'}\n`);
  }

  // ─── Kicker ──────────────────────────────────────────────────

  console.log('═'.repeat(70));
  console.log('  Same table. Same query. Different cleartext.');
  console.log('  The math is the access control.');
  console.log('');
  console.log('  Every query: signed, hash-chained, append-only.');
  console.log("  Delete a record? The DB won't let you.");
  console.log('  Bypass the DB? The hash chain breaks and everyone knows.');
  console.log('');
  console.log('  The IMF just told every securities regulator they need agent');
  console.log("  accountability and audit trails. Nvidia's 17 ISV partners");
  console.log('  need this. None of them have it.');
  console.log('═'.repeat(70) + '\n');

  await scope.close();
}

function printResultTable(rows: Record<string, unknown>[]): void {
  if (rows.length === 0) {
    console.log('  (no rows)');
    return;
  }

  const cols = Object.keys(rows[0]);
  const widths = cols.map((c) =>
    Math.max(
      c.length,
      ...rows.map((r) => {
        const val = r[c];
        const str =
          typeof val === 'string' && val.length > 24
            ? val.slice(0, 21) + '...'
            : String(val ?? 'NULL');
        return str.length;
      }),
    ),
  );

  // Header
  console.log('  ' + cols.map((c, i) => c.padEnd(widths[i])).join(' │ '));
  console.log('  ' + widths.map((w) => '─'.repeat(w)).join('─┼─'));

  // Rows
  for (const row of rows) {
    const cells = cols.map((c, i) => {
      const val = row[c];
      const str =
        typeof val === 'string' && val.length > 24
          ? val.slice(0, 21) + '...'
          : String(val ?? 'NULL');
      return str.padEnd(widths[i]);
    });
    console.log('  ' + cells.join(' │ '));
  }
}
