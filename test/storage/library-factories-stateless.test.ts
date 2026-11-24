import { describe, it, expect, beforeAll } from 'vitest';
import { createMockSession, VcVerifier, InMemoryRevocationStore } from '#index.js';

describe('Library factories are stateless', () => {
  // createMockSession requires dev mode; Vitest isolation restores NODE_ENV after this file.
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
  });

  it('createMockSession has no shared state across verifier instances', () => {
    const v1 = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const v2 = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const s1 = createMockSession(v1, 'Alice');
    const s2 = createMockSession(v2, 'Alice');
    expect(s1).not.toBe(s2);
  });
});
