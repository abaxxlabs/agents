import { logSafeError } from './safe-diagnostics.mjs';

/** A requested visitor runtime does not exist on this replica. */
export class VisitorSessionNotFoundError extends Error {}

/**
 * Track the live SDK runtimes of this replica. Sessions are resolved from the
 * signed cookie and the shared session store; this registry only owns local
 * resources.
 */
export function createVisitorSessionRegistry({
  createRuntime,
  runtimeOptions = {},
  now = () => Date.now(),
}) {
  if (typeof createRuntime !== 'function') throw new Error('Visitor session registry requires a runtime factory');
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const runtimes = new Map();
  let closing = false;
  let closeAllPromise;

  async function createRuntimeFor(sandboxId) {
    if (closing) throw new Error('Visitor runtime registry is closing');
    if (typeof sandboxId !== 'string' || sandboxId.length === 0) {
      throw new TypeError('sandboxId must be a non-empty string');
    }
    if (runtimes.has(sandboxId)) throw new Error(`Visitor runtime ${sandboxId} already exists`);
    const runtime = await createRuntime({ ...runtimeOptions, sandboxId });
    if (closing) {
      try {
        await runtime.close();
      } catch (err) {
        logSafeError(console, 'error', 'Visitor runtime cleanup failed after shutdown started', err, { sandboxId });
      }
      throw new Error('Visitor runtime registry is closing');
    }
    runtimes.set(sandboxId, { runtime, createdAt: now(), lastActivityAt: now() });
    return runtime;
  }

  function getRuntime(sandboxId) {
    const entry = runtimes.get(sandboxId);
    if (!entry) throw new VisitorSessionNotFoundError(`Visitor runtime ${sandboxId} is not available on this replica`);
    return entry.runtime;
  }

  function hasRuntime(sandboxId) {
    return runtimes.has(sandboxId);
  }

  async function closeRuntime(sandboxId) {
    const entry = runtimes.get(sandboxId);
    if (!entry) return null;
    runtimes.delete(sandboxId);
    try {
      await entry.runtime.close();
    } catch (err) {
      runtimes.set(sandboxId, entry);
      throw err;
    }
    return true;
  }

  function touchRuntime(sandboxId) {
    const entry = runtimes.get(sandboxId);
    if (entry) entry.lastActivityAt = now();
    return Boolean(entry);
  }

  async function expireLocal({ absoluteTtlMs, inactivityTtlMs }) {
    const at = now();
    const expired = [];
    for (const [sandboxId, entry] of [...runtimes.entries()]) {
      if (at - entry.createdAt < absoluteTtlMs && at - entry.lastActivityAt < inactivityTtlMs) continue;
      runtimes.delete(sandboxId);
      expired.push({ sandboxId, runtime: entry.runtime });
    }
    const failures = [];
    for (const entry of expired) {
      try {
        await entry.runtime.close();
      } catch (err) {
        runtimes.set(entry.sandboxId, { runtime: entry.runtime, createdAt: 0, lastActivityAt: 0 });
        failures.push(err);
      }
    }
    return {
      expired: expired.map(({ sandboxId }) => ({ sandboxId })),
      failures,
    };
  }

  function closeAll() {
    if (closeAllPromise) return closeAllPromise;
    closing = true;
    closeAllPromise = (async () => {
      const closedSandboxIds = [];
      const failures = [];
      for (const [sandboxId, entry] of [...runtimes.entries()]) {
        runtimes.delete(sandboxId);
        try {
          await entry.runtime.close();
          closedSandboxIds.push(sandboxId);
        } catch (err) {
          failures.push(err);
        }
      }
      return { closedSandboxIds, failures };
    })();
    return closeAllPromise;
  }

  return {
    createRuntime: createRuntimeFor,
    getRuntime,
    hasRuntime,
    touchRuntime,
    expireLocal,
    closeRuntime,
    closeAll,
    get size() {
      return runtimes.size;
    },
  };
}
