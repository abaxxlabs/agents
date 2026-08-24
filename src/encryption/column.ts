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

/** AES-256-GCM column encryption primitives. Pool-dependent ops live in `src/sql/column-keys.ts`. */

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import type { MasterKey } from '#crypto/master-key.js';
import { DecryptionFailedError } from '#errors/index.js';

const VERSION = 0x01;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const HEADER_LENGTH = 1 + IV_LENGTH + AUTH_TAG_LENGTH + 1; // 30 bytes

// Sentinel preserves SQL NULL round trips. The visible type code still identifies NULL ciphertexts.
const NULL_SENTINEL = Buffer.from('__AGENTS_NULL__');

enum TypeCode {
  TEXT = 0x01,
  INTEGER = 0x02,
  FLOAT = 0x03,
  BOOLEAN = 0x04,
  JSONB = 0x05,
  DATE = 0x06,
  TIMESTAMP = 0x07,
  NULL = 0xff,
}

function inferTypeCode(value: unknown): TypeCode {
  if (value === null || value === undefined) return TypeCode.NULL;
  if (typeof value === 'string') return TypeCode.TEXT;
  if (typeof value === 'number') return Number.isInteger(value) ? TypeCode.INTEGER : TypeCode.FLOAT;
  if (typeof value === 'boolean') return TypeCode.BOOLEAN;
  if (value instanceof Date) return TypeCode.TIMESTAMP;
  if (typeof value === 'object') return TypeCode.JSONB;
  return TypeCode.TEXT;
}

function serializeValue(value: unknown, typeCode: TypeCode): Buffer {
  if (typeCode === TypeCode.NULL) return NULL_SENTINEL;

  let str: string;
  switch (typeCode) {
    case TypeCode.TEXT:
      str = String(value);
      break;
    case TypeCode.INTEGER:
    case TypeCode.FLOAT:
      str = String(value);
      break;
    case TypeCode.BOOLEAN:
      str = value ? 'true' : 'false';
      break;
    case TypeCode.JSONB:
      str = JSON.stringify(value);
      break;
    case TypeCode.DATE:
    case TypeCode.TIMESTAMP:
      str = value instanceof Date ? value.toISOString() : String(value);
      break;
    default:
      str = String(value);
  }

  return Buffer.from(str, 'utf-8');
}

function deserializeValue(buf: Buffer, typeCode: TypeCode): unknown {
  if (typeCode === TypeCode.NULL) return null;
  if (buf.equals(NULL_SENTINEL)) return null;

  const str = buf.toString('utf-8');
  switch (typeCode) {
    case TypeCode.TEXT:
      return str;
    case TypeCode.INTEGER:
      return parseInt(str, 10);
    case TypeCode.FLOAT:
      return parseFloat(str);
    case TypeCode.BOOLEAN:
      return str === 'true';
    case TypeCode.JSONB:
      return JSON.parse(str);
    case TypeCode.DATE:
      return new Date(str);
    case TypeCode.TIMESTAMP:
      return new Date(str);
    default:
      return str;
  }
}

/**
 * Encrypt a value with AES-256-GCM and a fresh random 96-bit IV.
 * Returns `[version][IV][authTag][typeCode][ciphertext]`; length and type metadata remain visible.
 */
export function encrypt(value: unknown, columnKey: Buffer): Buffer {
  const typeCode = inferTypeCode(value);
  const plaintext = serializeValue(value, typeCode);

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', columnKey, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const result = Buffer.alloc(HEADER_LENGTH + encrypted.length);
  result[0] = VERSION;
  iv.copy(result, 1);
  authTag.copy(result, 1 + IV_LENGTH);
  result[1 + IV_LENGTH + AUTH_TAG_LENGTH] = typeCode;
  encrypted.copy(result, HEADER_LENGTH);

  return result;
}

/** Decrypt a value encrypted with `encrypt()`. Throws on tamper or wrong key. */
export function decrypt(ciphertext: Buffer, columnKey: Buffer): unknown {
  if (ciphertext.length < HEADER_LENGTH) {
    throw new DecryptionFailedError('unknown', 'Ciphertext too short');
  }

  const version = ciphertext[0];
  if (version !== VERSION) {
    throw new DecryptionFailedError('unknown', `Unsupported wire format version: ${version}`);
  }

  const iv = ciphertext.subarray(1, 1 + IV_LENGTH);
  const authTag = ciphertext.subarray(1 + IV_LENGTH, 1 + IV_LENGTH + AUTH_TAG_LENGTH);
  const typeCode = ciphertext[1 + IV_LENGTH + AUTH_TAG_LENGTH] as TypeCode;
  const encrypted = ciphertext.subarray(HEADER_LENGTH);

  try {
    const decipher = createDecipheriv('aes-256-gcm', columnKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return deserializeValue(decrypted, typeCode);
  } catch {
    // GCM throws on auth tag mismatch: ciphertext tampered, IV/tag corrupted, or wrong key.
    // Fail closed with an opaque message so callers cannot distinguish the cause via error text.
    throw new DecryptionFailedError('unknown', 'Decryption failed, encrypted with a different key');
  }
}

/** Generate a new 32-byte AES-256 column key. */
export function generateColumnKey(): Buffer {
  return randomBytes(32);
}

/** Encrypt a column key with the master key for storage. */
export function wrapColumnKey(columnKey: Buffer, masterKey: MasterKey): Buffer {
  return encrypt(columnKey.toString('hex'), masterKey) as Buffer;
}

/** Decrypt a column key wrapped with `wrapColumnKey()`. */
export function unwrapColumnKey(wrappedKey: Buffer, masterKey: MasterKey): Buffer {
  const hex = decrypt(wrappedKey, masterKey) as string;
  return Buffer.from(hex, 'hex');
}

/** Check Postgres SQLSTATE 42P01 (`undefined_table`). Pinned to SQLSTATE because message text varies by locale. */
export function isUndefinedTableError(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === '42P01'
  );
}

/** Decrypt authorized encrypted columns; preserve unscoped encrypted values as encoded data for defense in depth. */
export function decryptRow(
  row: Record<string, unknown>,
  scopeColumns: string[],
  tableName: string,
  columnKeys: Map<string, Buffer>,
  encryptedColumns: Set<string>,
): { decrypted: Record<string, unknown>; columnsDecrypted: string[]; columnsEncrypted: string[] } {
  const result: Record<string, unknown> = {};
  const columnsDecrypted: string[] = [];
  const columnsEncrypted: string[] = [];

  for (const [col, value] of Object.entries(row)) {
    const tableCol = `${tableName}.${col}`;

    if (!encryptedColumns.has(tableCol)) {
      result[col] = value;
      continue;
    }

    const columnKey = columnKeys.get(tableCol);
    if (!columnKey) {
      result[col] = value;
      columnsEncrypted.push(tableCol);
      continue;
    }

    if (scopeColumns.includes(tableCol)) {
      try {
        const buf = value instanceof Buffer ? value : Buffer.from(value as string, 'base64');
        result[col] = decrypt(buf, columnKey);
        columnsDecrypted.push(tableCol);
      } catch {
        result[col] = value instanceof Buffer ? value.toString('base64') : value;
        columnsEncrypted.push(tableCol);
      }
    } else {
      result[col] = value instanceof Buffer ? value.toString('base64') : value;
      columnsEncrypted.push(tableCol);
    }
  }

  return { decrypted: result, columnsDecrypted, columnsEncrypted };
}

export type { ColumnKeyRecord, EncryptedColumnMeta, ColumnKeyMap } from './types.js';
