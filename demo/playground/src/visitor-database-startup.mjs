import { createVisitorDatabaseProvisioner } from './visitor-database-provisioner.mjs';
import { logSafeError } from './safe-diagnostics.mjs';

/** Run the old visitor database sweep without making startup depend on cleanup success. */
export async function cleanupVisitorDatabasesAtStartup({
  adminPool,
  adminDatabaseUrl,
  appDatabaseUrl,
  templateDatabaseName,
  provisioner: existingProvisioner,
  logger = console,
  createProvisioner = createVisitorDatabaseProvisioner,
}) {
  try {
    if (!adminPool) throw new Error('Administrative database connection is not configured');
    const provisioner = existingProvisioner ?? await createProvisioner({
      adminPool,
      adminDatabaseUrl,
      appDatabaseUrl,
      templateDatabaseName,
    });
    const result = await provisioner.cleanupVisitorDatabases();
    logger.info('Visitor database startup cleanup completed', {
      deletedCount: result.deleted.length,
      failedCount: result.failed.length,
    });
    for (const { databaseName, error } of result.failed) {
      logSafeError(
        logger,
        'warn',
        'Visitor database startup cleanup could not remove a candidate; continuing startup',
        error,
        databaseName ? { databaseName } : undefined,
      );
    }
    return result;
  } catch (error) {
    logSafeError(logger, 'warn', 'Visitor database startup cleanup could not complete; continuing startup', error);
    return { deleted: [], failed: [{ databaseName: null, error }] };
  }
}
