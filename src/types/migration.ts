export const IDENTITY_MIGRATION_CREDENTIAL = 'IdentityMigrationCredential';

export interface MigrationCredentialClaims {
  previousDid: string;
  oidcSubject: string;
  migrationMethod: string;
  oidcIssuer: string;
  migratedAt: string;
}

export interface MigrationAuditFields {
  oldDid: string;
  newDid: string;
  migrationCredentialHash: string;
  oidcIssuer: string;
  agentsMigrated: number;
  contextEntriesMigrated: number;
  gracePeriodExpiresAt: string;
}
