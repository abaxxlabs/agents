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

import { describe, it, expect } from 'vitest';
import { inspect } from 'node:util';
import {
  REDACTED_MASTER_KEY,
  REDACTED_SIGNER,
  withRedactedSerialization,
} from '../src/crypto/redact.js';
import { createSigner } from '../src/auth/did-key.js';
import { generateDidKey } from '../src/auth/did-key.js';

// ─── shared constants ──────────────────────────────────────────────
describe('redaction constants', () => {
  it('REDACTED_MASTER_KEY is a recognisable marker', () => {
    expect(REDACTED_MASTER_KEY).toBe('[REDACTED 32 bytes]');
  });

  it('REDACTED_SIGNER is a recognisable marker', () => {
    expect(REDACTED_SIGNER).toBe('[AgentSigner]');
  });
});

// ─── createSigner redaction ────────────────────────────────────────
describe('createSigner redaction', () => {
  const { privateKey } = generateDidKey();
  const signer = createSigner(privateKey);
  const privateKeyHex = Buffer.from(privateKey).toString('hex');

  it('JSON.stringify returns the redaction marker, not key bytes', () => {
    const json = JSON.stringify(signer);
    expect(json).not.toContain(privateKeyHex);
    expect(json).toContain(REDACTED_SIGNER);
  });

  it('util.inspect returns the redaction marker', () => {
    const out = inspect(signer, { depth: 5 });
    expect(out).not.toContain(privateKeyHex);
    expect(out).toContain(REDACTED_SIGNER);
  });

  it('console.log path (default inspect) does not leak key bytes', () => {
    const out = inspect(signer);
    expect(out).not.toContain(privateKeyHex);
  });

  it('signJwt still works after redaction wiring', () => {
    const jwt = signer.signJwt({ sub: 'test' });
    expect(jwt.split('.')).toHaveLength(3);
  });
});

// ─── withRedactedSerialization helper ──────────────────────────────
describe('withRedactedSerialization', () => {
  it('adds toJSON and inspect.custom to a plain object', () => {
    const secret = Buffer.alloc(32, 0xff);
    const obj = withRedactedSerialization(
      { secret, safe: 'visible' },
      () => ({ safe: 'visible', secret: REDACTED_MASTER_KEY }),
    );

    const json = JSON.stringify(obj);
    expect(json).toContain(REDACTED_MASTER_KEY);
    expect(json).not.toContain(secret.toString('hex'));

    const inspected = inspect(obj, { depth: 5 });
    expect(inspected).toContain(REDACTED_MASTER_KEY);
    expect(inspected).not.toContain(secret.toString('hex'));
  });

  it('can be applied to a frozen object via pre-freeze call', () => {
    const obj = Object.freeze(
      withRedactedSerialization(
        { value: 42 },
        () => ({ value: '[HIDDEN]' }),
      ),
    );
    expect(JSON.parse(JSON.stringify(obj)).value).toBe('[HIDDEN]');
  });

  it('toJSON and inspect.custom are not enumerable', () => {
    const obj = withRedactedSerialization({ a: 1 }, () => ({ a: '[X]' }));
    expect(Object.keys(obj)).toEqual(['a']);
  });
});
