import { randomBytes } from 'node:crypto';
import { createVisitorRuntime } from './visitor-runtime.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/** A session was requested after registry shutdown began. */
export class VisitorRegistryClosingError extends Error {}

/** The registry has no capacity for another visitor session. */
export class VisitorSessionCapacityError extends Error {}

/** A requested visitor session does not exist. */
export class VisitorSessionNotFoundError extends Error {}

/** A requested visitor session is not available for use. */
export class VisitorSessionUnavailableError extends Error {}

/** Closing a visitor runtime or dropping its database failed. */
export class VisitorSessionCleanupError extends Error {
  constructor(sessionId, { closeError, dropError }) {
    super(`Failed to clean up visitor session ${sessionId}`, { cause: dropError ?? closeError });
    this.sessionId = sessionId;
    this.closeError = closeError;
    this.dropError = dropError;
  }
}

function createSessionId() {
  return randomBytes(32).toString('base64url');
}

function deferred() {
  let resolve;
  const promise = new Promise((nextResolve) => { resolve = nextResolve; });
  return { promise, resolve };
}

/**
 * Associate opaque visitor session IDs with isolated runtimes and coordinate their cleanup.
 */
export function createVisitorSessionRegistry({
  provisioner,
  createRuntime = createVisitorRuntime,
  runtimeOptions = {},
  generateSessionId = createSessionId,
  maxSessions,
  inactivityTtlMs,
  now = () => Date.now(),
}) {
  if (!provisioner?.createVisitorDatabase || !provisioner?.dropVisitorDatabase) {
    throw new Error('Visitor session registry requires a database provisioner');
  }
  if (typeof createRuntime !== 'function') throw new Error('Visitor session registry requires a runtime factory');
  if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) {
    throw new RangeError('maxSessions must be a positive safe integer');
  }
  if (!Number.isSafeInteger(inactivityTtlMs) || inactivityTtlMs < 1) {
    throw new RangeError('inactivityTtlMs must be a positive safe integer');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a function');

  const sessions = new Map();
  const pendingCreations = new Set();
  let closing = false;
  let closeAllPromise;

  function sessionIdForCreation() {
    let sessionId;
    do {
      sessionId = generateSessionId();
    } while (sessions.has(sessionId) || [...pendingCreations].some((creation) => creation.sessionId === sessionId));
    return sessionId;
  }

  function unavailable(sessionId, state) {
    return new VisitorSessionUnavailableError(`Visitor session ${sessionId} is ${state}`);
  }

  function activeEntry(sessionId) {
    const entry = sessions.get(sessionId);
    if (!entry) throw new VisitorSessionNotFoundError(`Visitor session ${sessionId} does not exist`);
    if (entry.state !== 'active') throw unavailable(sessionId, entry.state);
    return entry;
  }

  async function compensateCreation(creation) {
    let closeError;
    let dropError;
    if (creation.runtime) {
      try {
        await creation.runtime.close();
      } catch (err) {
        closeError = err;
      }
    }
    if (creation.databaseName) {
      try {
        await provisioner.dropVisitorDatabase(creation.databaseName);
      } catch (err) {
        dropError = err;
      }
    }
    return { closeError, dropError };
  }

  function retainFailedCreation(creation, { closeError, dropError }, creationError) {
    if (creationError instanceof Error) {
      creationError.cleanupSessionId = creation.sessionId;
      creationError.cleanupError ??= dropError;
    }
    const timestamp = new Date(now());
    sessions.set(creation.sessionId, {
      runtime: creation.runtime,
      databaseName: creation.databaseName,
      lastActivity: timestamp,
      state: 'cleanup_failed',
      deletePromise: undefined,
      closeError,
    });
  }

  async function createSession() {
    if (closing) throw new VisitorRegistryClosingError('Visitor session registry is closing');
    if (sessions.size + pendingCreations.size >= maxSessions) {
      throw new VisitorSessionCapacityError('Visitor session registry is at capacity');
    }

    const creation = { sessionId: sessionIdForCreation(), completion: deferred() };
    pendingCreations.add(creation);
    try {
      let database;
      try {
        database = await provisioner.createVisitorDatabase();
      } catch (err) {
        if (err?.orphanedDatabaseName) {
          creation.databaseName = err.orphanedDatabaseName;
          retainFailedCreation(creation, { dropError: err.cleanupError }, err);
        }
        throw err;
      }
      creation.databaseName = database.databaseName;
      try {
        creation.runtime = await createRuntime({ ...runtimeOptions, ...database });
      } catch (err) {
        const { dropError } = await compensateCreation(creation);
        if (dropError) {
          retainFailedCreation(creation, { dropError }, err);
          logSafeError(console, 'error', 'Visitor database cleanup failed after runtime initialization error', dropError);
        }
        throw err;
      }

      if (closing) {
        const cleanup = await compensateCreation(creation);
        if (cleanup.closeError || cleanup.dropError) {
          if (cleanup.dropError) retainFailedCreation(creation, cleanup);
          throw new VisitorSessionCleanupError(creation.sessionId, cleanup);
        }
        creation.cancelledForShutdown = true;
        throw new VisitorRegistryClosingError('Visitor session registry is closing');
      }

      const timestamp = new Date(now());
      sessions.set(creation.sessionId, {
        runtime: creation.runtime,
        databaseName: creation.databaseName,
        lastActivity: timestamp,
        state: 'active',
        deletePromise: undefined,
      });
      return { sessionId: creation.sessionId, runtime: creation.runtime };
    } catch (err) {
      creation.error = err;
      throw err;
    } finally {
      pendingCreations.delete(creation);
      creation.completion.resolve({ error: creation.cancelledForShutdown ? undefined : creation.error });
    }
  }

  function cleanupError(sessionId, closeError, dropError) {
    return new VisitorSessionCleanupError(sessionId, { closeError, dropError });
  }

  function deleteActiveSession(sessionId, entry) {
    entry.state = 'deleting';
    const operation = (async () => {
      let closeError;
      let dropError;
      try {
        await entry.runtime.close();
      } catch (err) {
        closeError = err;
      }
      try {
        await provisioner.dropVisitorDatabase(entry.databaseName);
      } catch (err) {
        dropError = err;
      }

      if (dropError) {
        entry.state = 'cleanup_failed';
        entry.closeError = closeError;
        throw cleanupError(sessionId, closeError, dropError);
      }

      sessions.delete(sessionId);
      if (closeError) throw cleanupError(sessionId, closeError, undefined);
    })();
    entry.deletePromise = operation;
    operation.catch(() => {
      if (sessions.get(sessionId) === entry && entry.state === 'cleanup_failed') entry.deletePromise = undefined;
    });
    return operation;
  }

  function retryDrop(sessionId, entry) {
    entry.state = 'deleting';
    const operation = (async () => {
      try {
        await provisioner.dropVisitorDatabase(entry.databaseName);
      } catch (err) {
        entry.state = 'cleanup_failed';
        throw cleanupError(sessionId, entry.closeError, err);
      }
      sessions.delete(sessionId);
    })();
    entry.deletePromise = operation;
    operation.catch(() => {
      if (sessions.get(sessionId) === entry && entry.state === 'cleanup_failed') entry.deletePromise = undefined;
    });
    return operation;
  }

  function deleteSession(sessionId) {
    const entry = sessions.get(sessionId);
    if (!entry) throw new VisitorSessionNotFoundError(`Visitor session ${sessionId} does not exist`);
    if (entry.state === 'deleting') return entry.deletePromise;
    if (entry.state === 'cleanup_failed') return retryDrop(sessionId, entry);
    return deleteActiveSession(sessionId, entry);
  }

  function closeAll() {
    if (closeAllPromise) return closeAllPromise;
    closing = true;
    closeAllPromise = (async () => {
      const failures = [];
      const pending = [...pendingCreations];
      const pendingResults = await Promise.all(pending.map((creation) => creation.completion.promise));
      for (const [index, result] of pendingResults.entries()) {
        if (result.error) failures.push({ sessionId: pending[index].sessionId, error: result.error });
      }

      const entries = [...sessions.entries()];
      const results = await Promise.allSettled(entries.map(([sessionId]) => deleteSession(sessionId)));
      for (const [index, result] of results.entries()) {
        if (result.status === 'rejected') failures.push({ sessionId: entries[index][0], error: result.reason });
      }

      if (failures.length) {
        throw new AggregateError(failures.map(({ error }) => error), `Failed to clean up visitor sessions: ${failures.map(({ sessionId }) => sessionId).join(', ')}`);
      }
    })();
    return closeAllPromise;
  }

  function getSession(sessionId) {
    return activeEntry(sessionId).runtime;
  }

  function touchSession(sessionId) {
    const entry = activeEntry(sessionId);
    entry.lastActivity = new Date(now());
    return { lastActivity: entry.lastActivity };
  }

  async function cleanupExpiredSessions() {
    const cleanupTime = now();
    const attempts = [];
    for (const [sessionId, entry] of sessions) {
      if (entry.state === 'cleanup_failed' ||
        (entry.state === 'active' && cleanupTime - entry.lastActivity.getTime() >= inactivityTtlMs)) {
        attempts.push({ sessionId, promise: deleteSession(sessionId) });
      }
    }

    const results = await Promise.allSettled(attempts.map(({ promise }) => promise));
    const failures = results.flatMap((result, index) => result.status === 'rejected'
      ? [{ sessionId: attempts[index].sessionId, error: result.reason }]
      : []);
    if (failures.length) {
      throw new AggregateError(
        failures.map(({ error }) => error),
        `Failed to clean up expired visitor sessions: ${failures.map(({ sessionId }) => sessionId).join(', ')}`,
      );
    }
  }

  return { createSession, getSession, touchSession, deleteSession, cleanupExpiredSessions, closeAll };
}
