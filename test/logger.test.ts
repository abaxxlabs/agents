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
