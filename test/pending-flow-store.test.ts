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

  it('consumes a registered flow with the matching code verifier', () => {
    const store = new PendingFlowStore();
    store.register('state-1', 'verifier-1');
    expect(() => store.consume('state-1', 'verifier-1')).not.toThrow();
  });

  it('rejects a second consume of the same state (single-use)', () => {
    const store = new PendingFlowStore();
    store.register('state-1', 'verifier-1');
    store.consume('state-1', 'verifier-1');
    expect(() => store.consume('state-1', 'verifier-1')).toThrow(PendingFlowError);
  });

  it('rejects an unknown state (CSRF protection)', () => {
    const store = new PendingFlowStore();
    expect(() => store.consume('never-registered', 'verifier-1')).toThrow(PendingFlowError);
  });

  it('rejects an expired flow (TTL enforcement)', () => {
    const store = new PendingFlowStore(1000);
    store.register('state-1', 'verifier-1');
    vi.advanceTimersByTime(1000 + 1);
    expect(() => store.consume('state-1', 'verifier-1')).toThrow(
      'OAuth authorization flow has expired. Restart the authorization flow.',
    );
  });

  it('uses a 10-minute default TTL', () => {
    const store = new PendingFlowStore();
    store.register('boundary', 'verifier-1');
    vi.advanceTimersByTime(10 * 60 * 1000);
    expect(() => store.consume('boundary', 'verifier-1')).not.toThrow();

    store.register('expired', 'verifier-2');
    vi.advanceTimersByTime(10 * 60 * 1000 + 1);
    expect(() => store.consume('expired', 'verifier-2')).toThrow(PendingFlowError);
  });

  it('accepts a flow at the exact TTL boundary but rejects one millisecond later', () => {
    const store = new PendingFlowStore(1000);
    store.register('boundary', 'verifier-1');
    vi.advanceTimersByTime(1000);
    expect(() => store.consume('boundary', 'verifier-1')).not.toThrow();

    store.register('boundary-2', 'verifier-2');
    vi.advanceTimersByTime(1001);
    expect(() => store.consume('boundary-2', 'verifier-2')).toThrow(PendingFlowError);
  });

  it('does not delete the flow on a verifier mismatch (anti-probing)', () => {
    const store = new PendingFlowStore();
    store.register('state-1', 'correct-verifier');

    expect(() => store.consume('state-1', 'wrong-verifier')).toThrow(PendingFlowError);

    // The flow must survive the mismatch — a subsequent consume with the
    // correct verifier (still within TTL) succeeds, proving it was not deleted.
    expect(() => store.consume('state-1', 'correct-verifier')).not.toThrow();
  });

  it('purges expired flows opportunistically when a new flow is registered', () => {
    const store = new PendingFlowStore(1000);
    store.register('flow-a', 'verifier-a');

    vi.advanceTimersByTime(1000 + 1);
    store.register('flow-b', 'verifier-b');

    expect(() => store.consume('flow-a', 'verifier-a')).toThrow(PendingFlowError);
    expect(() => store.consume('flow-b', 'verifier-b')).not.toThrow();
  });

  it('honors a custom TTL rather than the default', () => {
    const store = new PendingFlowStore(5000);
    store.register('state-1', 'verifier-1');

    vi.advanceTimersByTime(4999);
    expect(() => store.consume('state-1', 'verifier-1')).not.toThrow();

    store.register('state-2', 'verifier-2');
    vi.advanceTimersByTime(5001);
    expect(() => store.consume('state-2', 'verifier-2')).toThrow(PendingFlowError);
  });
});
