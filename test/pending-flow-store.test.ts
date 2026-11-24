import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PendingFlowStore, PendingFlowError } from '#auth/pending-flow-store.js';

describe('PendingFlowStore', () => {
  beforeEach(() => {
    // Fake only Date; faking the full timer suite deadlocks vitest's forks-pool hook scheduler.
    vi.useFakeTimers({ toFake: ['Date'] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('preserves a registered flow after a verifier mismatch and consumes it only once with the matching verifier', () => {
    const store = new PendingFlowStore();
    store.register('state-1', 'verifier-1');
    expect(() => store.consume('state-1', 'wrong-verifier')).toThrow(PendingFlowError);
    expect(() => store.consume('state-1', 'verifier-1')).not.toThrow();
    expect(() => store.consume('state-1', 'verifier-1')).toThrow(PendingFlowError);
  });

  it('rejects a registered flow after its TTL even with the matching verifier', () => {
    const store = new PendingFlowStore(1000);
    store.register('state-1', 'verifier-1');
    vi.setSystemTime(Date.now() + 1001);
    expect(() => store.consume('state-1', 'verifier-1')).toThrow(PendingFlowError);
  });

  it('rejects an unknown state (CSRF protection)', () => {
    const store = new PendingFlowStore();
    expect(() => store.consume('never-registered', 'verifier-1')).toThrow(PendingFlowError);
  });
});
