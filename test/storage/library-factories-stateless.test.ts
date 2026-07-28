import { describe, it, expect, beforeAll } from 'vitest';
import { createMockSession, VcVerifier, InMemoryRevocationStore } from '#index.js';

describe('Library factories are stateless', () => {
  // createMockSession requires dev mode (NODE_ENV guard). Set it for this
  // test file only; NODE_ENV restored by vitest isolation.
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
  });

  it('createMockSession produces distinct object references on repeat calls', () => {
    const verifier = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const s1 = createMockSession(verifier, 'TestHuman');
    const s2 = createMockSession(verifier, 'TestHuman');
    expect(s1).not.toBe(s2);
    expect(s1.humanDid).toBe(s2.humanDid);
  });

  it('createMockSession has no shared state across verifier instances', () => {
    const v1 = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const v2 = new VcVerifier({ revocationStore: new InMemoryRevocationStore() });
    const s1 = createMockSession(v1, 'Alice');
    const s2 = createMockSession(v2, 'Alice');
    expect(s1).not.toBe(s2);
  });

  it('library does NOT hold a session Map — only packages/server/ does', async () => {
    const { readFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const authFile = readFileSync(join(process.cwd(), 'src', 'auth', 'agent.ts'), 'utf8');
    const hasSessionMap = /\bMap<[^>]*(?:Session|session)[^>]*>/.test(authFile);
    expect(hasSessionMap).toBe(false);
  });
});
