/** Stop the janitor and HTTP acceptance before closing local runtimes, rows and shared pools. */
export async function shutdownVisitorServer({
  server,
  registry,
  janitor,
  sessionStore,
  directSqlPool,
  controlPool,
  sessionCookie,
}) {
  const failures = [];
  if (janitor) {
    try {
      await janitor.stop();
    } catch (err) {
      failures.push(err);
    }
  }
  try {
    await new Promise((resolve, reject) => {
      server.close((err) => err ? reject(err) : resolve());
    });
  } catch (err) {
    failures.push(err);
  }
  try {
    const {
      closedSandboxIds,
      failures: closeFailures,
    } = await registry.closeAll();
    failures.push(...closeFailures);
    if (closedSandboxIds.length > 0 && sessionStore) {
      try {
        await sessionStore.releaseMany({ sandboxIds: closedSandboxIds });
      } catch (err) {
        failures.push(err);
      }
    }
  } catch (err) {
    failures.push(err);
  }
  for (const pool of [directSqlPool, controlPool]) {
    if (!pool) continue;
    try {
      await pool.end();
    } catch (err) {
      failures.push(err);
    }
  }
  sessionCookie?.close();
  if (failures.length) throw new AggregateError(failures, 'Visitor Playground shutdown was incomplete');
}
