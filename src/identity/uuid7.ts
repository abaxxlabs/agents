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
 * UUID7 — RFC 9562 time-ordered unique identifier.
 *
 * 48-bit unix_ts_ms | 4-bit version (0111) | 12-bit rand_a | 2-bit variant (10) | 62-bit rand_b
 *
 * Time-ordered so audit queries and event sequences sort chronologically by JTI.
 * Used by presentation.ts for VP nonces (JTI claims).
 */

import { randomBytes } from 'node:crypto';

export function generateUuid7(): string {
  const now = Date.now();
  const tsHex = now.toString(16).padStart(12, '0');

  const rand = randomBytes(10);

  // time_low (8 hex) - time_mid (4 hex) - ver+rand_a (4 hex) - var+rand_b (4 hex) - rand_b (12 hex)
  const timeLow = tsHex.slice(0, 8);
  const timeMid = tsHex.slice(8, 12);

  // Version nibble (0111) + 12 bits of rand_a
  const randA = ((0x7 << 12) | (((rand[0] << 8) | rand[1]) & 0x0fff)).toString(16).padStart(4, '0');

  // Variant bits (10) + 6 bits of rand_b[0]
  const varByte = ((0x2 << 6) | (rand[2] & 0x3f)).toString(16).padStart(2, '0');
  const nextByte = rand[3].toString(16).padStart(2, '0');

  // Remaining 48 bits of rand_b
  const tail = Array.from(rand.slice(4, 10))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `${timeLow}-${timeMid}-${randA}-${varByte}${nextByte}-${tail}`;
}

export function extractUuid7Timestamp(uuid7: string): number | null {
  const hex = uuid7.replace(/-/g, '');
  if (hex.length !== 32) return null;
  if (hex[12] !== '7') return null;
  return parseInt(hex.slice(0, 12), 16);
}
