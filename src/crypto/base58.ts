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
 * Base58 encoding/decoding — Bitcoin alphabet.
 *
 * did:key identifiers use base58btc multibase encoding (prefix 'z').
 * Standard big-integer conversion with leading-zero ('1') preservation.
 * No padding, no multibase prefix — callers add 'z' for did:key.
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode a byte array to a base58btc string (Bitcoin alphabet, no prefix).
 */
export function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  // Preserve leading zero bytes as '1' characters
  for (const byte of bytes) {
    if (byte === 0) digits.push(0);
    else break;
  }
  return digits
    .reverse()
    .map((d) => ALPHABET[d])
    .join('');
}

/**
 * Decode a base58btc string (Bitcoin alphabet) back to a byte array.
 * Throws on invalid characters.
 */
export function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const idx = ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }

  const hex = num.toString(16).padStart(2, '0');
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const bytes = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
  }

  // Restore leading zero bytes from leading '1' characters
  let leadingZeros = 0;
  for (const char of str) {
    if (char === '1') leadingZeros++;
    else break;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(new Uint8Array(bytes), leadingZeros);
  return result;
}
