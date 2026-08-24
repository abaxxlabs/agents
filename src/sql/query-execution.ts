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

import type { Pool } from 'pg';
import { decryptRow } from '#encryption/index.js';

export interface QueryRunnerOptions {
  pool: Pool;
  columnKeys: Map<string, Buffer>;
  encryptedColumns: Set<string>;
}

export interface QueryExecutionInput {
  sql: string;
  params?: unknown[];
  table: string;
  scopeColumns: string[];
}

export interface QueryExecutionResult {
  decryptedRows: Record<string, unknown>[];
  columnsDecrypted: string[];
  columnsEncrypted: string[];
}

/**
 * Executes an authorized query and decrypts encrypted columns covered by the
 * scope. The projection policy rejects out-of-scope column references before
 * this runner is called.
 */
export class QueryRunner {
  private pool: Pool;
  private columnKeys: Map<string, Buffer>;
  private encryptedColumns: Set<string>;

  constructor(options: QueryRunnerOptions) {
    this.pool = options.pool;
    this.columnKeys = options.columnKeys;
    this.encryptedColumns = options.encryptedColumns;
  }

  async execute(input: QueryExecutionInput): Promise<QueryExecutionResult> {
    const queryResult = await this.pool.query(input.sql, input.params);

    const allColumnsDecrypted = new Set<string>();
    const allColumnsEncrypted = new Set<string>();
    const decryptedRows = queryResult.rows.map((row) => {
      const { decrypted, columnsDecrypted, columnsEncrypted } = decryptRow(
        row as Record<string, unknown>,
        input.scopeColumns,
        input.table,
        this.columnKeys,
        this.encryptedColumns,
      );
      columnsDecrypted.forEach((c) => allColumnsDecrypted.add(c));
      columnsEncrypted.forEach((c) => allColumnsEncrypted.add(c));
      return decrypted;
    });

    return {
      decryptedRows,
      columnsDecrypted: Array.from(allColumnsDecrypted),
      columnsEncrypted: Array.from(allColumnsEncrypted),
    };
  }
}
