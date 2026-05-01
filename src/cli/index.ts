#!/usr/bin/env node
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
 * Agents++ CLI
 *
 * Commands:
 *   init           - Initialize config + encryption keys for a Postgres database
 *   demo           - Run the 90-second demo scenario
 *   encrypt        - Encrypt a column in-place
 *   verify         - Verify an audit trail export
 *   status         - Show middleware status
 *   migrate-check  - Read-only scan to categorize a project for the v0.9.10.0 BYOK migration
 */

import { Command } from 'commander';
import {
  applyStdinMasterKeyToEnv,
  argvContainsDeprecatedMasterKeyFlag,
  printMasterKeyArgvRejected,
  warnIfMasterKeyEnvWasPresentAtProcessStart,
} from './master-key-cli.js';
import { buildServeChildEnv } from './serve-env.js';

const program = new Command();

program
  .name('agents')
  .description('Agents++ — encryption-based identity and access control for AI agents')
  .version('0.5.0');

program
  .command('init')
  .description('Initialize agents tables and encryption keys')
  .option(
    '--db <url>',
    'PostgreSQL connection string (or set DATABASE_URL env var)',
    process.env.DATABASE_URL,
  )
  .option('--abaxx-one <url>', 'Abaxx One tenant URL', 'https://one.abaxx.tech')
  .option('--client-id <id>', 'OIDC client ID', 'agents')
  .option('--encrypt-columns <list>', 'Comma-separated list of table.column to encrypt')
  .option(
    '--master-key-stdin',
    'Read master key (64 hex chars) from stdin until EOF (see AGENTS_MASTER_KEY)',
  )
  .option('--config <path>', 'Output config file path', 'agents.config.json')
  .action(async (options) => {
    if (!options.db) {
      console.error('Error: --db <url> is required (or set DATABASE_URL env var).');
      console.error('Example: agents init --db postgresql://postgres:postgres@localhost:5432/mydb');
      process.exit(1);
    }
    const { runInit } = await import('./init.js');
    await runInit(options);
  });

program
  .command('demo')
  .description('Run the 90-second demo scenario')
  .option(
    '--db <url>',
    'PostgreSQL connection string',
    'postgresql://postgres:postgres@localhost:5432/agents_demo',
  )
  .option(
    '--master-key-stdin',
    'Read master key (64 hex chars) from stdin until EOF (see AGENTS_MASTER_KEY)',
  )
  .action(async (options) => {
    const { runDemo } = await import('./demo.js');
    await runDemo(options);
  });

program
  .command('encrypt <table.column>')
  .description('Encrypt a column in-place (e.g., patients.dob)')
  .option('--db <url>', 'PostgreSQL connection string')
  .option('--config <path>', 'Config file path')
  .option(
    '--master-key-stdin',
    'Read master key (64 hex chars) from stdin until EOF (see AGENTS_MASTER_KEY)',
  )
  .action(async (tableColumn, options) => {
    const { runEncrypt } = await import('./encrypt.js');
    await runEncrypt(tableColumn, options);
  });

program
  .command('verify <source>')
  .description('Verify audit records from a JSON file or database URL')
  .option('--agent <did>', 'Filter by agent DID')
  .option('--since <date>', 'Filter records after date (ISO 8601)')
  .option('--json', 'Output results as JSON')
  .action(async (source, options) => {
    const { runVerify } = await import('./verify.js');
    await runVerify(source, options);
  });

program
  .command('status')
  .description('Show middleware status (database, encryption, agents, audit)')
  .option('--db <url>', 'PostgreSQL connection string')
  .option('--config <path>', 'Config file path')
  .option('--abaxx-one <url>', 'Abaxx One tenant URL')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    const { runStatus } = await import('./status.js');
    await runStatus(options);
  });

program
  .command('mcp')
  .description('Start the MCP server for AI agent integration')
  .option(
    '--db <url>',
    'PostgreSQL connection string (or set DATABASE_URL env var)',
    process.env.DATABASE_URL,
  )
  .option('--mock <name>', 'Mock human DID for development')
  .option('--transport <type>', 'Transport: stdio or http', 'stdio')
  .option('--port <number>', 'HTTP port', '8080')
  .option('--tls-cert <path>', 'TLS certificate file')
  .option('--tls-key <path>', 'TLS private key file')
  .option('--insecure', 'Allow plaintext HTTP (dev/test only)')
  .option(
    '--allow-no-auth',
    'Allow HTTP MCP without bearer tokens (NODE_ENV=development|test only; not for production)',
  )
  .option(
    '--single-instance',
    'Acknowledge single-instance deployment; required when NODE_ENV=production with default storage',
  )
  .action(async (options) => {
    if (!options.db) {
      console.error('Error: --db <url> is required (or set DATABASE_URL env var).');
      console.error('Example: agents mcp --db postgresql://postgres:postgres@localhost:5432/mydb');
      process.exit(1);
    }
    const { startMcpServer } = await import('../mcp/index.js');
    await startMcpServer({
      db: options.db,
      mock: options.mock,
      transport: options.transport as 'stdio' | 'http',
      port: parseInt(options.port, 10),
      tlsCert: options.tlsCert,
      tlsKey: options.tlsKey,
      insecure: options.insecure,
      allowNoAuth: options.allowNoAuth,
      singleInstance: options.singleInstance,
    });
  });

program
  .command('migrate-check')
  .description('Read-only scan to categorize this project for the v0.9.10.0 BYOK migration')
  .option('--cwd <path>', 'Directory to scan (default: current working directory)')
  .option('--json', 'Emit machine-readable JSON instead of human-readable report')
  .action(async (options) => {
    const { runMigrateCheck } = await import('./migrate-check.js');
    await runMigrateCheck({
      cwd: options.cwd,
      json: options.json,
    });
  });

program
  .command('serve')
  .description('Start the REST API server (Swagger UI at /docs)')
  .option(
    '--db <url>',
    'PostgreSQL connection string (or set DATABASE_URL env var)',
    process.env.DATABASE_URL,
  )
  .option('--port <number>', 'HTTP port', '3100')
  .option('--columns <list>', 'Comma-separated encrypted columns (e.g., patients.dob,patients.ssn)')
  .option(
    '--master-key-stdin',
    'Read master key (64 hex chars) from stdin until EOF (see AGENTS_MASTER_KEY)',
  )
  .action(async (options) => {
    if (!options.db) {
      console.error('Error: --db <url> is required (or set DATABASE_URL env var).');
      console.error(
        'Example: agents serve --db postgresql://postgres:postgres@localhost:5432/mydb',
      );
      process.exit(1);
    }
    const { execSync } = await import('node:child_process');
    const { resolve, dirname } = await import('node:path');
    const { fileURLToPath } = await import('node:url');

    const __dirname = dirname(fileURLToPath(import.meta.url));
    const serverDir = resolve(__dirname, '../../packages/server');

    const env = buildServeChildEnv({
      db: options.db,
      port: options.port,
      columns: options.columns,
    });

    try {
      execSync('npx tsx src/index.ts', { cwd: serverDir, env, stdio: 'inherit' });
    } catch {
      process.exit(1);
    }
  });

if (argvContainsDeprecatedMasterKeyFlag(process.argv)) {
  printMasterKeyArgvRejected();
  process.exit(1);
}

if (process.argv.includes('--master-key-stdin')) {
  try {
    applyStdinMasterKeyToEnv();
  } catch (err) {
    console.error('[agents] Error:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

warnIfMasterKeyEnvWasPresentAtProcessStart();

program.parseAsync(process.argv).catch((err) => {
  console.error('[agents] Error:', err.message);
  process.exit(1);
});
