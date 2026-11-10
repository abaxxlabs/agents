/** Stop HTTP acceptance before closing visitor runtimes, then release the admin pool. */
export async function shutdownVisitorServer({ server, registry, adminPool }) {
  const failures = [];
  try {
    await new Promise((resolve, reject) => {
      server.close((err) => err ? reject(err) : resolve());
    });
  } catch (err) {
    failures.push(err);
  }
  try {
    await registry.closeAll();
  } catch (err) {
    failures.push(err);
  }
  try {
    await adminPool.end();
  } catch (err) {
    failures.push(err);
  }
  if (failures.length) throw new AggregateError(failures, 'Visitor Playground shutdown was incomplete');
}
