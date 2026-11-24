import { logSafeError } from './safe-diagnostics.mjs';

/**
 * Shared cleanup path for HTTP session invalidation and the periodic janitor.
 * The caller decides whether the shared row is released here or was already
 * claimed; both paths close the local runtime.
 */
export function createVisitorSessionCleaner({ registry, sessionStore, logger = console }) {
  if (typeof registry?.closeRuntime !== 'function') {
    throw new TypeError('Visitor session cleaner requires a runtime registry');
  }
  if (typeof sessionStore?.release !== 'function') {
    throw new TypeError('Visitor session cleaner requires a session store');
  }

  async function closeLocalRuntime(sandboxId) {
    try {
      await registry.closeRuntime(sandboxId);
    } catch (err) {
      logSafeError(logger, 'error', 'Visitor runtime cleanup failed', err, { sandboxId });
    }
  }

  return {
    async release(sandboxId) {
      try {
        await sessionStore.release({ sandboxId });
      } catch (err) {
        logSafeError(logger, 'error', 'Visitor session row cleanup failed', err);
      }
      await closeLocalRuntime(sandboxId);
    },

    async dispose({ sandboxId }) {
      await closeLocalRuntime(sandboxId);
    },
  };
}
