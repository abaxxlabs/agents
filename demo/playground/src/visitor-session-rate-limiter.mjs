const MAX_TRACKED_ADDRESSES = 4096;

export function createVisitorSessionRateLimiter({ maxNewSessions, windowMs, now = () => Date.now() }) {
  if (!Number.isSafeInteger(maxNewSessions) || maxNewSessions < 1) {
    throw new RangeError('maxNewSessions must be a positive safe integer');
  }
  if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
    throw new RangeError('windowMs must be a positive safe integer');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const buckets = new Map();

  function removeExpired(timestamp) {
    for (const [address, bucket] of buckets) {
      if (timestamp - bucket.startedAt >= windowMs) buckets.delete(address);
    }
  }

  return {
    consumeNewSession(address) {
      const key = typeof address === 'string' && address ? address : 'unknown';
      const timestamp = now();
      let bucket = buckets.get(key);

      if (bucket && timestamp - bucket.startedAt >= windowMs) {
        buckets.delete(key);
        bucket = undefined;
      }

      if (bucket) {
        if (bucket.count >= maxNewSessions) {
          return { allowed: false, retryAfterMs: Math.max(1, bucket.startedAt + windowMs - timestamp) };
        }
        bucket.count += 1;
        return { allowed: true };
      }

      if (buckets.size >= MAX_TRACKED_ADDRESSES) removeExpired(timestamp);
      if (buckets.size >= MAX_TRACKED_ADDRESSES) {
        return { allowed: false, retryAfterMs: windowMs };
      }

      buckets.set(key, { startedAt: timestamp, count: 1 });
      return { allowed: true };
    },
  };
}
