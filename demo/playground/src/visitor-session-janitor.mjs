import { logSafeError } from './safe-diagnostics.mjs';

/**
 * Expire sessions on every replica. The store claims rows with SKIP LOCKED, so
 * concurrent janitors delete each row once; a failed sweep retries a bounded
 * number of times before waiting for the next tick.
 */
export function createVisitorSessionJanitor({
  store,
  onExpired = async () => {},
  onSweep = async () => {},
  intervalMs,
  batchSize,
  maxAttempts,
  retryDelayMs,
  logger = console,
  metrics,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  if (!store?.claimExpired) throw new TypeError('Visitor session janitor requires a session store');
  for (const [value, name] of [
    [intervalMs, 'intervalMs'],
    [batchSize, 'batchSize'],
    [maxAttempts, 'maxAttempts'],
    [retryDelayMs, 'retryDelayMs'],
  ]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive safe integer`);
  }
  if (typeof onExpired !== 'function') throw new TypeError('onExpired must be a function');
  if (typeof onSweep !== 'function') throw new TypeError('onSweep must be a function');

  let timer;
  let stopping = false;
  let running;

  async function runOnce() {
    let expired = [];
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        expired = await store.claimExpired({ limit: batchSize });
        break;
      } catch (err) {
        if (attempt === maxAttempts) {
          logSafeError(logger, 'error', 'Visitor session janitor sweep failed', err);
          break;
        }
        await sleep(retryDelayMs * attempt);
      }
    }
    for (const entry of expired) {
      metrics?.counter('playground_sessions_expired_total', { reason: entry.reason });
      try {
        await onExpired(entry);
      } catch (err) {
        logSafeError(logger, 'error', 'Expired visitor session cleanup failed', err, { sandboxId: entry.sandboxId });
      }
    }
    try {
      await store.cleanupRateWindows();
    } catch (err) {
      logSafeError(logger, 'error', 'Origin rate window cleanup failed', err);
    }
    try {
      await onSweep();
    } catch (err) {
      logSafeError(logger, 'error', 'Local visitor runtime sweep failed', err);
    }
    return expired.length;
  }

  function schedule() {
    if (stopping) return;
    timer = setTimeout(async () => {
      timer = undefined;
      running = runOnce().finally(() => {
        running = undefined;
        schedule();
      });
      await running;
    }, intervalMs);
    timer.unref?.();
  }

  return {
    start() {
      if (timer || running) return;
      stopping = false;
      schedule();
    },

    async stop() {
      stopping = true;
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
      await running;
    },

    runOnce,
  };
}
