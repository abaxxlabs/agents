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

// Alphabet and symbol order differ from RFC 4648 base32, so a standard base32
// decoder returns wrong bytes here rather than failing.
const ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';

const LOOKUP = new Map<string, number>([...ALPHABET].map((char, index) => [char, index] as const));

/**
 * Decode a z-base-32 string, the encoding used by `did:dht` identifiers.
 *
 * @throws Error when the input contains a character outside the alphabet.
 */
export function zbase32Decode(input: string): Uint8Array {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;

  for (const char of input) {
    const value = LOOKUP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid z-base-32 character: '${char}'`);
    }
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }

  return new Uint8Array(out);
}

/** Encode bytes as z-base-32, zero-padding trailing bits in the final character. */
export function zbase32Encode(bytes: Uint8Array): string {
  let acc = 0;
  let bits = 0;
  let out = '';

  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >> bits) & 31];
    }
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];

  return out;
}
