// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * MigrationExecutor — atomic DID migration from did:key to did:dht.
 *
 * Triggered by an IdentityMigrationCredential detected in a VP by VcVerifier.
 * The migration trust anchor is checked before any DB work — even if the
 * upstream verifier accepts a credential from a consumer-configurable
 * LocalTrustAnchorStore, the executor independently rejects unless the issuer
 * is in the build-time-baked migration trust list.
 */

import type { Pool } from 'pg';
import type {
  RegisteredAgent,
  MigrationCredentialClaims,
  MigrationAuditFields,
  AgentSigner,
} from './types.js';
import { DidAliasRegistry, type DidAlias } from './did-alias.js';
import { AuditLogger, hashCredential } from './audit-logger.js';
import type { Logger } from './logger.js';
import { defaultLogger } from './logger.js';
import {
  MigrationTrustAnchor,
  UntrustedMigrationIssuerError,
  decodeJwtIssuer,
  type TrustedMigrationCredential,
} from './discovery/migration-trust-anchor.js';
import { PrecisionLossError } from './errors.js';

/**
 * Parse a PostgreSQL bigint string (e.g. COUNT(*) result) into a JS number,
 * throwing {@link PrecisionLossError} if the value exceeds Number.MAX_SAFE_INTEGER.
 */
function safeParsePgCount(raw: string): number {
  const n = BigInt(raw);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new PrecisionLossError(raw);
  }
  return Number(n);
}

// Default grace period: 7 days. Long enough for all credentials to expire
// naturally (default maxTtl is 24h), plus buffer for weekends and clock skew.
const DEFAULT_GRACE_PERIOD_DAYS = 7;

export interface MigrationResult {
  success: boolean;
  agentsMigrated: number;
  contextEntriesMigrated: number;
  aliasCreated: boolean;
  gracePeriodExpiresAt: Date;
  /** Set to true if this credential was already processed (idempotent no-op). */
  alreadyMigrated: boolean;
}

export interface MigrationExecutorOptions {
  pool: Pool;
  /** In-memory agents Map from AgentScope — updated synchronously after DB commit. */
  agents: Map<string, RegisteredAgent>;
  aliasRegistry: DidAliasRegistry;
  auditLogger: AuditLogger;
  /** Grace period in days. Default: 7. */
  gracePeriodDays?: number;
  /**
   * Trust anchor for migration credential issuers. Defaults to a fresh
   * MigrationTrustAnchor() that reads from the build-time-baked
   * OFFICIAL_MIGRATION_ISSUERS constant. Callers may pass a pre-populated
   * instance — for example, after extracting issuer DIDs from a verified
   * AbaxxOne parent credential chain — but the only mutation path on a fresh
   * instance is `addFromParentCredentialChain()`. There is intentionally no
   * env-var or admin-API path to seed trusted migration issuers.
   *
   * **Production safety:** only `'baked'` and `'parent-credential-chain'`
   * trust-anchor sources are valid in production. Injecting a
   * MigrationTrustAnchor whose entries originate from `'env'` or `'api'`
   * sources (e.g. via LocalTrustAnchorStore) silently defeats the build-time
   * issuer hardening that prevents forked deployments from rebinding
   * identities. Test suites may use `addFromParentCredentialChain()` to
   * whitelist a test issuer DID — that is the intended test-only override
   * path, not a pattern for production wiring.
   */
  migrationTrustAnchor?: MigrationTrustAnchor;
  /** Optional diagnostic logger. */
  logger?: Logger;
}

export class MigrationExecutor {
  readonly #pool: Pool;
  readonly #agents: Map<string, RegisteredAgent>;
  readonly #aliasRegistry: DidAliasRegistry;
  readonly #auditLogger: AuditLogger;
  readonly #gracePeriodDays: number;
  readonly #migrationTrustAnchor: MigrationTrustAnchor;
  readonly #logger: Logger;

  constructor(options: MigrationExecutorOptions) {
    this.#pool = options.pool;
    this.#agents = options.agents;
    this.#aliasRegistry = options.aliasRegistry;
    this.#auditLogger = options.auditLogger;
    this.#gracePeriodDays = options.gracePeriodDays ?? DEFAULT_GRACE_PERIOD_DAYS;
    this.#migrationTrustAnchor = options.migrationTrustAnchor ?? new MigrationTrustAnchor();
    this.#logger = options.logger ?? defaultLogger;
  }

  /**
   * The trust anchor used by this executor.
   *
   * Exposed so callers can pass it to
   * `asTrustedMigrationCredential(jwt, executor.migrationTrustAnchor)`
   * to produce the branded type accepted by `execute()`.
   */
  get migrationTrustAnchor(): MigrationTrustAnchor {
    return this.#migrationTrustAnchor;
  }

  /**
   * Execute an identity migration based on a verified IdentityMigrationCredential.
   *
   * The runtime trust gate re-checks the issuer DID regardless of the compile-time
   * brand — JavaScript callers, `as` casts, and MCP bridges are all covered.
   *
   * Sequence: trust anchor check → claim validation → idempotency check →
   * previousDid validation → SERIALIZABLE DB transaction → in-memory update →
   * audit record.
   *
   * @param migrationCredentialJwt — compact-JWS credential branded as `TrustedMigrationCredential`.
   *   Obtain via `asTrustedMigrationCredential(jwt, anchor)`.
   * @param claims — pre-extracted claims from the credential payload
   * @param newDid — the target did:dht to rebind to
   * @param signer — optional AgentSigner for audit logging
   */
  async execute(
    migrationCredentialJwt: TrustedMigrationCredential,
    claims: MigrationCredentialClaims,
    newDid: string,
    signer?: AgentSigner,
  ): Promise<MigrationResult> {
    // Trust gate first — prevents probing migration history via untrusted issuers.
    const issuerDid = decodeJwtIssuer(migrationCredentialJwt);
    if (!this.#migrationTrustAnchor.isTrusted(issuerDid)) {
      throw new UntrustedMigrationIssuerError(issuerDid);
    }

    if (
      !claims.previousDid ||
      !claims.oidcSubject ||
      !claims.oidcIssuer ||
      !claims.migrationMethod
    ) {
      throw new Error('Migration credential claims must not be empty');
    }

    const credentialHash = hashCredential(migrationCredentialJwt);

    // Idempotency: check if this credential has already been processed.
    if (this.#aliasRegistry.hasCredential(credentialHash)) {
      return {
        success: true,
        agentsMigrated: 0,
        contextEntriesMigrated: 0,
        aliasCreated: false,
        gracePeriodExpiresAt: new Date(),
        alreadyMigrated: true,
      };
    }

    const oldDid = claims.previousDid;

    // Validate previousDid is a did:key (free-tier only).
    if (!oldDid.startsWith('did:key:')) {
      throw new Error(
        `Migration previousDid must be a did:key (free tier). Got: ${oldDid.split(':').slice(0, 2).join(':')}`,
      );
    }

    // Validate newDid is a did:dht (AbaxxOne).
    if (!newDid.startsWith('did:dht:')) {
      throw new Error(
        `Migration target must be a did:dht (AbaxxOne). Got: ${newDid.split(':').slice(0, 2).join(':')}`,
      );
    }

    const gracePeriodExpiresAt = new Date();
    gracePeriodExpiresAt.setDate(gracePeriodExpiresAt.getDate() + this.#gracePeriodDays);

    // Execute atomic migration in a SERIALIZABLE transaction.
    // SERIALIZABLE prevents audit-chain corruption from concurrent writes.
    const client = await this.#pool.connect();
    let agentsMigrated = 0;
    let contextEntriesMigrated = 0;

    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

      // Double-check idempotency inside the transaction (race condition guard).
      const existingAlias = await client.query(
        'SELECT 1 FROM agent_did_aliases WHERE credential_hash = $1',
        [credentialHash],
      );
      if (existingAlias.rows.length > 0) {
        await client.query('ROLLBACK');
        return {
          success: true,
          agentsMigrated: 0,
          contextEntriesMigrated: 0,
          aliasCreated: false,
          gracePeriodExpiresAt,
          alreadyMigrated: true,
        };
      }

      // Verify previousDid exists as an owner in the agent registry.
      const ownerCheck = await client.query(
        'SELECT COUNT(*) AS cnt FROM agents WHERE owner_did = $1',
        [oldDid],
      );
      if (safeParsePgCount(ownerCheck.rows[0].cnt) === 0) {
        await client.query('ROLLBACK');
        throw new Error(
          `Migration previousDid ${oldDid} has no agents registered. Nothing to migrate.`,
        );
      }

      // Step 1: INSERT alias record.
      await client.query(
        `INSERT INTO agent_did_aliases
          (old_did, new_did, credential_hash, oidc_subject, oidc_issuer, migrated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6)`,
        [
          oldDid,
          newDid,
          credentialHash,
          claims.oidcSubject,
          claims.oidcIssuer,
          gracePeriodExpiresAt,
        ],
      );

      // Step 2: UPDATE agents.owner_did.
      const agentResult = await client.query(
        'UPDATE agents SET owner_did = $1 WHERE owner_did = $2',
        [newDid, oldDid],
      );
      agentsMigrated = agentResult.rowCount ?? 0;

      // Step 3: UPDATE agent_context.owner_did.
      // Updated atomically (not via alias expansion) so the "database enforces
      // the boundary" invariant holds.
      const contextResult = await client.query(
        'UPDATE agent_context SET owner_did = $1 WHERE owner_did = $2',
        [newDid, oldDid],
      );
      contextEntriesMigrated = contextResult.rowCount ?? 0;

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }

    // Step 4: Update in-memory state AFTER DB commit.
    // Alias must be registered BEFORE the agents Map update so grace-period
    // DID comparison is live before any query sees the new ownerDid.
    const alias: DidAlias = {
      oldDid,
      newDid,
      credentialHash,
      oidcSubject: claims.oidcSubject,
      oidcIssuer: claims.oidcIssuer,
      migratedAt: new Date(),
      expiresAt: gracePeriodExpiresAt,
    };
    this.#aliasRegistry.addAlias(alias);

    // Update agents Map: change ownerDid for all affected agents.
    for (const [, agent] of this.#agents) {
      if (agent.ownerDid === oldDid) {
        agent.ownerDid = newDid;
      }
    }

    // Step 5: Log migration audit record.
    const migrationAuditFields: MigrationAuditFields = {
      oldDid,
      newDid,
      migrationCredentialHash: credentialHash,
      oidcIssuer: claims.oidcIssuer,
      agentsMigrated,
      contextEntriesMigrated,
      gracePeriodExpiresAt: gracePeriodExpiresAt.toISOString(),
    };

    await this.#auditLogger
      .logRejection(
        `Identity migration: ${oldDid} → ${newDid} (${agentsMigrated} agents, ${contextEntriesMigrated} context entries)`,
        'IDENTITY_MIGRATION',
        signer,
        {
          agentDid: newDid,
          ownerDid: newDid,
          sql: JSON.stringify(migrationAuditFields),
        },
      )
      .catch((err: unknown) => {
        // Best-effort: migration succeeded even if audit write fails.
        // The database changes are committed. Log the failure for diagnostics.
        this.#logger.error('[agents] Migration audit record failed', { error: err });
      });

    return {
      success: true,
      agentsMigrated,
      contextEntriesMigrated,
      aliasCreated: true,
      gracePeriodExpiresAt,
      alreadyMigrated: false,
    };
  }

  /**
   * Load existing aliases from the database. Call during initialization
   * to restore grace period state after restart.
   */
  async loadAliases(): Promise<number> {
    const result = await this.#pool.query(
      'SELECT old_did, new_did, credential_hash, oidc_subject, oidc_issuer, migrated_at, expires_at FROM agent_did_aliases WHERE expires_at > NOW()',
    );

    const aliases: DidAlias[] = result.rows.map((row: Record<string, unknown>) => ({
      oldDid: row.old_did as string,
      newDid: row.new_did as string,
      credentialHash: row.credential_hash as string,
      oidcSubject: row.oidc_subject as string,
      oidcIssuer: row.oidc_issuer as string,
      migratedAt: new Date(row.migrated_at as string | number | Date),
      expiresAt: new Date(row.expires_at as string | number | Date),
    }));

    this.#aliasRegistry.loadAliases(aliases);
    return aliases.length;
  }
}
