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

import { describe, expect, it } from 'vitest';
import { defaultLogger, getLogger, type Logger } from '../src/logger.js';

describe('getLogger', () => {
  it('returns defaultLogger when called with no argument', () => {
    expect(getLogger()).toBe(defaultLogger);
  });

  it('returns defaultLogger when injected is undefined', () => {
    expect(getLogger(undefined)).toBe(defaultLogger);
  });

  it('returns the injected logger when one is provided', () => {
    const customLogger: Logger = {
      warn() {},
      error() {},
    };
    expect(getLogger(customLogger)).toBe(customLogger);
  });
});
