# Migration: BYOK master key + injections boundary (v0.9.10.0)

**Audience:** anyone upgrading `@abaxxlabs/agents` from v0.9.6.0–v0.9.9.x to v0.9.10.0.
**Why this document exists:** v0.9.10.0 is a breaking change with two distinct axes:

1. **API shape**: `AgentScope.create(config, injections)` is now a two-parameter factory. The master key moves from `config.encryption.masterKey` (a hex string) to `injections.masterKey` (a 32-byte branded `MasterKey` Buffer). This is the BYOK ("bring your own key") boundary: the library no longer reads `AGENTS_MASTER_KEY` from the environment; consumers supply the key explicitly.
2. **Revocation enforcement** (drift correction). Pre-v0.9.10.0, the `IRevocationStore` interface and three adapters were available, but `AgentScope.create` could not receive an injected store. Every deployment used `InMemoryRevocationStore`, so revocation state was limited to a single process lifetime. This release adds the injection path so deployments can use a durable revocation store.

For the first migration, read this guide in full. For additional consumer projects, use the **decision tree** to identify the relevant worked example.

---

## Summary {#tldr}

For applications that read `AGENTS_MASTER_KEY` from the environment, the minimum required change is:

```ts
// before (v0.9.9.x)
const scope = await AgentScope.create({
  database: { connectionString: process.env.DATABASE_URL! },
  encryption: { masterKey: process.env.AGENTS_MASTER_KEY }, // ← hex string in config
});

// after (v0.9.10.0)
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();          // ← read once, at startup
const scope = await AgentScope.create(
  { database: { connectionString: process.env.DATABASE_URL! } },  // config (no encryption.masterKey)
  { masterKey },                                                  // injections
);
```

That is the migration for **case #1** below. If you do anything else with key material — KMS-sourced keys, key rotation during the upgrade, multi-instance deployment with revocation durability, mixed env-var-and-config-field usage — read the rest of this document.

---

## Decision tree: which case am I in?

Six questions. Answer the applicable ones in order. Each leaf maps to one of the four worked examples plus any additional guidance.

| # | Question | Yes | No |
|---|---|---|---|
| Q1 | Do you read `AGENTS_MASTER_KEY` from `process.env` today? | go to Q3 | go to Q2 |
| Q2 | Do you set `encryption.masterKey` in `AgentScopeConfig` (config-file or inline) today? | go to Q3 | **No key source** — see "If you currently have neither" in case #1 before migrating |
| Q3 | Are you planning to **change the key value** as part of this upgrade (KMS migration, key rotation, fresh key)? | go to Q4 | go to Q5 |
| Q4 | Are you currently env-only and keeping env as the key source? | **case #3** (env-only / new key) | **case #4** (config-sourced or moving to KMS / new key) |
| Q5 | Do you have **both** env reads AND `encryption.masterKey` set in config today? | **environment audit first** — the environment value took precedence; confirm the active key source, then follow case #1 or case #2 | go to Q6 |
| Q6 | Do you set `encryption.masterKey` in `AgentScopeConfig`? | **case #2** (config-hex / same-key) | **case #1** (env-only / same-key) |

Each case below stands alone — read only the one that applies.

If you are in **case #4**, also read the complete [`rewrapColumnKey` migration protocol](#rewrapcolumnkey-migration-protocol).

If you operate **multi-instance** or rely on **cross-restart revocation durability**, also read the [revocation-store injection](#revocation-store-injection-required-for-multi-instance) section regardless of which case you are in.

---

## Environment audit (do this first)

Before applying any worked example, audit the key material your codebase references. In v0.9.6.0–v0.9.9.x, `process.env.AGENTS_MASTER_KEY` took precedence over `config.encryption.masterKey` when both were set. From v0.9.10.0, only `injections.masterKey` supplies the key. Migrating from the wrong source can cause the application to start with an incorrect master key.

### Step 1 — grep the codebase

Run from the consumer project root:

```bash
# All references to the key, by name and by config field
grep -rn 'AGENTS_MASTER_KEY\|encryption\.masterKey' . \
  --exclude-dir=node_modules \
  --exclude-dir=dist \
  --exclude-dir=.git
```

Classify each hit:

- **Active env read**: `process.env.AGENTS_MASTER_KEY` in code (not a comment, not a doc).
- **Active config write**: `encryption: { masterKey: ... }` in a config object passed to `AgentScope.create`.
- **Active env write**: `process.env.AGENTS_MASTER_KEY = ...` (rare — typically demos / fixtures).
- **Documentation**: README, comments, JSDoc — leave for the doc-update pass after the migration lands.

### Step 2 — if you see hits in BOTH env-read AND config-write paths

**Confirm the active key source.** Before v0.9.10.0, the environment variable was authoritative and the configuration field was ignored. Identify the key used by the deployed application before migrating:

1. In a deployment shell, print **just the length** of the env var (never the value):
   ```bash
   node -e "console.log(process.env.AGENTS_MASTER_KEY?.length ?? 'unset')"
   ```
2. Compare against the config field's length. If they match in length but you are unsure they match byte-for-byte, treat the **env var** as canonical (that is what was actually wrapping your column keys) and discard the config field.
3. If the lengths differ, **do not proceed**. Recover the active environment value from your secret manager, retained environment configuration, or deployment template before migrating. This is the key used to wrap existing column keys; the configuration value was ignored.

Once you have the canonical key value identified, proceed to the worked example matching your starting state.

### Step 3 — automate it (optional)

Run the diagnostic CLI to generate a categorized report instead of reviewing search results manually:

```bash
npx @abaxxlabs/agents migrate-check
```

The script is read-only — it makes no edits, runs no migrations, sends no telemetry. It scans for `process.env.AGENTS_MASTER_KEY`, `encryption.masterKey`, and `AgentScope.create(` call sites, then prints "you are in case #N based on M matches at these lines." Useful when triaging across many repositories. Not yet required to upgrade.

---

## Case #1 — env-only, same key going forward

**You are here if:** you read `AGENTS_MASTER_KEY` from `process.env`, you do not set `encryption.masterKey` in config, and you are keeping the same key value.

**What changes:** the call site that today reads the env var inside `AgentScope.create` now reads it once at bootstrap and threads the resulting `Buffer` into `injections.masterKey`. No data rewrap. No new env vars.

### Before (v0.9.9.x)

```ts
import { AgentScope } from '@abaxxlabs/agents';

const scope = await AgentScope.create({
  database: { connectionString: process.env.DATABASE_URL! },
  encryption: {
    masterKey: process.env.AGENTS_MASTER_KEY, // hex string
  },
  // ...rest of config
});
```

### After (v0.9.10.0)

```ts
import { AgentScope } from '@abaxxlabs/agents';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

// Read once at startup. Throws MasterKeyMissingError if AGENTS_MASTER_KEY is
// unset; throws Error if it is set but not exactly 64 hex characters.
const masterKey = resolveMasterKeyFromEnv();

const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL! },
    // encryption block can be omitted entirely if you have no encrypted columns
    // declared here. If you do declare columns, the block stays — but no
    // masterKey field on it.
    // encryption: { columns: [...] },
  },
  { masterKey },
);
```

### Things to know

- `resolveMasterKeyFromEnv()` is the designated entry point for reading `AGENTS_MASTER_KEY`. Read it once at startup and pass the resulting `MasterKey` (a `Buffer` at runtime) explicitly through the application.
- Strict 64-hex-character validation occurs at this boundary. Truncated, padded, base64-encoded, or whitespace-contaminated environment values produce an explicit validation error before the library uses the key.
- If you also call `deriveSessionMacKey(...)` in your bootstrap (server consumers), pass the same `masterKey` Buffer to it. Do not call `resolveMasterKeyFromEnv()` twice.

### If you currently have neither (no env read, no config write)

The application was running with an undefined master key. Before v0.9.10.0, this could fail at the first encryption operation or remain undetected if no encrypted columns were registered. v0.9.10.0 rejects the configuration at construction with `MasterKeyMissingError`. Generate a key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Set it in your environment (`AGENTS_MASTER_KEY=<the hex>`) and follow case #1 above. Store the key securely; losing it prevents decryption of existing encrypted columns.

---

## Case #2 — config-hex, same key going forward

**You are here if:** you do not read `AGENTS_MASTER_KEY` from env, you DO set `encryption.masterKey` as a hex string in `AgentScopeConfig`, and you are keeping the same key value.

**What changes:** structural. The hex string moves out of config (it is no longer a config field at the type level) and becomes a `Buffer` in injections. Decoding moves to the consumer boundary.

### Before (v0.9.9.x)

```ts
import { AgentScope } from '@abaxxlabs/agents';

const config = await loadYourConfig(); // returns { encryption: { masterKey: '<64 hex chars>' }, ... }

const scope = await AgentScope.create(config);
```

### After (v0.9.10.0)

```ts
import { AgentScope } from '@abaxxlabs/agents';
import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';

const config = await loadYourConfig();

// parseMasterKeyHex applies the same strict 64-hex validation as
// resolveMasterKeyFromEnv. Use this for any non-env hex source — config files,
// secret-manager responses, KMS callbacks that return hex.
const masterKey = parseMasterKeyHex(config.encryption.masterKey);

// Strip the masterKey field from config — it no longer belongs there.
const { masterKey: _, ...restEncryption } = config.encryption;
const cleanConfig = {
  ...config,
  encryption: restEncryption,
};

const scope = await AgentScope.create(cleanConfig, { masterKey });
```

### Things to know

- `AgentScopeConfig.encryption.masterKey` is no longer part of the configuration type. TypeScript rejects it on a config object passed to `AgentScope.create`, while the runtime ignores extra properties. Update each affected call site to use the injection parameter.
- If your config file format includes the master key as a string field (YAML / JSON / TOML), you do not have to remove it from the file. Strip it at the consumer boundary right before calling `AgentScope.create`. The library never sees it.
- If you eventually move to KMS, `parseMasterKeyHex` is the helper you keep — it accepts a hex string from any source. KMS APIs that return raw bytes go through `asMasterKey(buf)` instead (see case #4).

---

## Case #3 — env-only, NEW key (rotating, moving to KMS, fresh credential)

**You are here if:** you read `AGENTS_MASTER_KEY` from env today, and you are changing the key value at the same time as the upgrade.

Do not migrate the API shape and rotate the key in one step. Master-key rotation requires re-wrapping every encrypted column key under the new master key. Replacing the environment value without re-wrapping causes column-key loading to fail with `MasterKeyMismatchError`, preventing application startup.

The correct sequence:

1. **First, complete case #1 with the OLD key.** Get to v0.9.10.0 on your existing key. Verify the application boots and decrypts column data. Commit and deploy.
2. **Then run the rewrap migration** to move from old key to new key. See [the `rewrapColumnKey` migration protocol](#rewrapcolumnkey-migration-protocol) below.
3. **Then update the env var (or move to KMS) in your bootstrap.**

If separate deployments are not feasible, for example during an urgent response to a compromised key, complete steps 1–3 as sequential phases within one maintenance window while the application is quiesced.

The full procedure is documented in [the `rewrapColumnKey` migration protocol](#rewrapcolumnkey-migration-protocol). Read it before you start.

---

## Case #4 — config-hex with NEW key, or any case combined with rewrap

**You are here if:** you are changing the master-key value at the same time as the API-shape migration. Common variants:

- Moving from env-sourced hex to KMS-sourced bytes.
- Rotating the key as part of a security incident response.
- Moving from a shared dev key to a per-environment production key.

**Steps:**

1. **Migrate the API shape first under the OLD key.** Apply case #1 or case #2 (whichever fits your starting state) without changing the key value. Deploy. Verify.
2. **Run the rewrap migration.** Use `rewrapColumnKey` on every registered column to re-wrap each column key under the NEW master key. Procedure below.
3. **Switch the bootstrap to read the new key.** This is the deploy that actually swaps the source.

### Bootstrap shapes for non-env key sources

If you are sourcing the new key from KMS / Vault / a secrets manager, the boundary code is:

```ts
import { AgentScope } from '@abaxxlabs/agents';
import { asMasterKey } from '@abaxxlabs/agents';

// KMS / Vault / Secrets Manager call returns raw bytes (not hex).
const rawBytes: Buffer = await yourKmsClient.getKey('agents-master-key');

// asMasterKey validates 32-byte length and brands. Throws if not 32 bytes.
const masterKey = asMasterKey(rawBytes);

const scope = await AgentScope.create(config, { masterKey });
```

If KMS returns hex (some HSMs do), use `parseMasterKeyHex(hex)` instead — same validation as `resolveMasterKeyFromEnv` minus the env-var lookup.

`asMasterKey` is the smart constructor for the branded `MasterKey` type. Any code path that constructs a `Buffer` from raw bytes (KMS, file read, custom decoding) goes through it. The brand is the type-system signal that this Buffer has been validated as 32 bytes and intended-as-master-key — not just any Buffer that happens to be the right length.

---

## `rewrapColumnKey` migration protocol

Re-wrapping a column key under a new master key is a six-step, write-quiesced procedure. The library exposes the primitive (`rewrapColumnKey`) but does not run the protocol; write quiescence is a deployment responsibility.

**Why quiesce writes:** during the rewrap window, the `agent_keys` row for a column is locked (`SELECT ... FOR UPDATE`). New writes against the encrypted column would block on the lock, but more importantly: if you concurrently rotate AND rewrap the same column, the wrapped key swap order matters and you want the system idle while you do this work.

### The six steps {#the-five-steps}

1. **Quiesce writes** to encrypted columns. Use a maintenance flag, read-only mode, an application-level advisory lock, or a queue pause. Reads may continue during this window, but writes to encrypted columns must stop.
2. **Snapshot** `agent_keys` (mandatory). The wrapped-key bytes and the `agent_did` / `table_name` / `column_name` triple are the only authoritative record of which column-key wraps which column. A failed rewrap mid-pass is recoverable from snapshot; a failure with no snapshot is not.
   ```bash
   psql "$DATABASE_URL" -c "\\copy (SELECT * FROM agent_keys) TO 'agent_keys_pre_rewrap_$(date +%Y%m%d_%H%M).csv' CSV HEADER"
   ```
3. **Verify-old.** Confirm the OLD master key unwraps every column key listed in `agent_keys`. Resolve any verification failure before proceeding with the rewrap.
   ```ts
   import { verifyAllColumnKeys } from '@abaxxlabs/agents/sql';
   import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';

   const oldMasterKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_OLD!);
   const before = await verifyAllColumnKeys(pool, oldMasterKey);
   if (before.failed.length > 0) {
     console.error(`Pre-rewrap verification failed for ${before.failed.length} row(s):`);
     for (const f of before.failed) console.error(`  ${f.table}.${f.col}: ${f.error}`);
     throw new Error('Pre-rewrap state is broken — recover before proceeding.');
   }
   ```
   `verifyAllColumnKeys` is read-only — one `SELECT` against `agent_keys`, no transactions, no row locks. Safe to call against a live system.
4. **Rewrap.** Iterate over `agent_keys` and call `rewrapColumnKey` once per row:
   ```ts
   import { rewrapColumnKey } from '@abaxxlabs/agents/sql';
   import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';

   const oldMasterKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_OLD!);
   const newMasterKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_NEW!);

   // The `agent_keys` table is keyed by (table_name, column_name). The
   // `agentDid` parameter on rewrapColumnKey is for audit attribution only —
   // pass the human DID running the migration (recorded as the row's owner
   // in agent_audit). Pull it from your migration tooling, not from agent_keys.
   const adminDid = process.env.MIGRATION_ADMIN_DID!;

   const rows = await pool.query(
     `SELECT table_name, column_name FROM agent_keys`
   );

   for (const row of rows.rows) {
     await rewrapColumnKey({
       pool,
       agentDid: adminDid,
       tableName: row.table_name,
       columnName: row.column_name,
       oldMasterKey,
       newMasterKey,
     });
   }
   ```
   Each call is its own transaction: `SELECT ... FOR UPDATE` on the `agent_keys` row, `unwrapColumnKey(oldMasterKey, ...)`, `wrapColumnKey(newMasterKey, ...)`, `UPDATE agent_keys SET encrypted_key = ...`, audit append, and commit. If a call throws, that row is unchanged and remains wrapped under the OLD key. Do not start the application with the new master key while rows remain wrapped under different keys.
5. **Verify-new.** Confirm the NEW master key unwraps every column key. If a row still requires the OLD key, re-run the rewrap loop or call `rewrapColumnKey` for that row. Proceed to step 6 only after verification succeeds for every registered column key.
   ```ts
   const newMasterKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_NEW!);
   const after = await verifyAllColumnKeys(pool, newMasterKey);
   if (after.failed.length > 0) {
     console.error(`Post-rewrap verification failed for ${after.failed.length} row(s):`);
     for (const f of after.failed) console.error(`  ${f.table}.${f.col}: ${f.error}`);
     // Re-run rewrap for the listed rows, or call rewrapColumnKey for each
     // failed entry individually. Do not cut over to the new key until this
     // report is empty.
   }
   ```
6. **Cutover.** Update the bootstrap to source the NEW master key. Restart all instances and resume writes.

### Failure modes

- **`KeyRotationFailedError` thrown mid-step-4 with `phase: 'unwrap-old-key'`**: the supplied OLD master key does not match the key used to wrap the column key in `agent_keys`. Review the environment-source audit and check for column-key rotations performed after the snapshot. Compare the current state with the pre-rewrap CSV.
- **`KeyRotationFailedError` with `phase: 'wrap-new-key'`**: the NEW master key failed length validation. Check `asMasterKey` is being called with a 32-byte Buffer.
- **`KeyRotationFailedError` with `phase: 'update-agent-keys'`**: a database write failure, which may result from a transient network interruption or a deadlock with concurrent writers. Confirm that writes are quiesced before retrying. Retrying a row already wrapped under the new key fails at `phase: 'unwrap-old-key'` without modifying that row.
- **Incomplete rewrap at the end of the maintenance window**: rows wrapped under the new key cannot be read with the old master key, and rows wrapped under the old key cannot be read with the new master key. **Do not resume traffic in this state.** Complete the rewrap for the remaining rows (preferred), or restore the affected rows using the snapshot from step 2. Select the recovery procedure based on operational risk and recovery time.

### What this protocol is NOT

- **Not online.** v0.9.10.0 does not support a dual-key transition window where the same column simultaneously accepts old-key and new-key reads. That capability would require key-generation tracking and dual-key cryptographic support. Re-wrapping therefore requires a maintenance window.
- **Not cross-application.** If multiple applications share the same Postgres database and the same encrypted columns (atypical but possible), all of them must restart against the new master key in the same window. Otherwise the application that is still on the old master will throw `MasterKeyMismatchError` on first decrypt.
- **Not partial.** Do not rewrap "the important columns" and leave the rest. The library expects a single master key per process. A column-by-column phased migration requires per-column master-key isolation, which the v0.9.10.0 surface does not expose.

---

## MAC-key co-rotation note (server consumers only)

This concerns server deployments that persist sessions via `PostgresSessionStore` or `SqliteSessionStore` (v0.9.8.0+).

The session-envelope MAC key is HKDF-derived from the master key (`HKDF_CONTEXT_SESSION_MAC` context string). Changing the master key changes the MAC key. Any session envelope written under the OLD master key has a MAC tag derived from the OLD MAC key — and will fail integrity verification when re-read under the NEW master key.

This is expected behavior. Sessions are short-lived (default 4h TTL). Integrity verification rejects the request with `401 SESSION_INTEGRITY_FAILED`, and the user must authenticate again. The stored row remains present but cannot be used to restore a session.

**Operational implication during BYOK rotation:** switching to the new master key invalidates existing sessions in the durable store. Account for the resulting re-authentication requirements:

- **Single-instance deployments**: authentication may be interrupted during restart, including for users with an active workflow.
- **Multi-instance deployments with sticky sessions**: session invalidation affects users as their assigned instance restarts during the rolling deployment.
- **Multi-instance deployments without sticky sessions, expecting cross-instance rehydrate**: session restoration returns 401 for pre-cutover envelopes, requiring users to authenticate again. If this interruption is not acceptable, schedule the BYOK cutover during low-traffic hours or a maintenance window.

There is no MAC-key versioning in v0.9.10.0. Sessions written before the cutover and sessions written after live under different MAC keys with no way for the new instance to verify the old envelopes.

You can pre-clear the session table at cutover time to avoid users getting 401s on stale envelopes:

```sql
-- Run in the maintenance window, before resuming traffic on the new master key.
DELETE FROM sessions;
```

This is optional — leaving the rows lets `pruneExpired` clean them up at TTL — but explicit deletion makes the post-cutover state cleaner.

---

## Revocation-store injection (required for multi-instance)

Whether your migration case is #1, #2, #3, or #4, a separate decision applies if you operate **multi-instance** OR rely on **revocation durability across process restarts**: you must inject a durable `RevocationStore`. The default behavior when `injections.storage` is omitted is:

- Server consumer: auto-detects a default `PostgresRevocationStore` when `DATABASE_URL` is set and attempts migration 007 on boot when the migration file is available. Single INFO log line on startup names the active store. No code change needed.
- Direct library consumer: `AgentScope.create` constructs a default `PostgresStorageBackend` from `config.database.connectionString`, but **does not call `.initialize()` on it**. Three concrete consequences:
  - The revocation cache starts cold (first hits round-trip to Postgres).
  - Cross-instance coherency polling never starts — peer-instance revocations are seen only on cache miss.
  - Migration 007 must be applied before relying on durable revocation checks.

  This default-backend behavior is correct for tests and demos with pre-applied schemas; it is **not** sufficient for production multi-instance, and it is **not** safe for consumers who run AgentScope before applying schema migrations.

The current API couples migration execution to storage lifecycle initialization. `initialize()` executes SQL only when it finds a `migrations/` directory; the published npm package does not include that directory, so consumers must apply the migration files externally. When a directory is present, initialization starts the ordered sequence from its first file, has no migration-history table, and is not generally repeat-safe on an already migrated schema. Apply schema changes through controlled deployment tooling; do not call `initialize()` concurrently or on every process boot as an apply-once migration runner. The following shows construction and first-time initialization only:

```ts
import { createStorageBackend, deriveSessionMacKey } from '@abaxxlabs/agents';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();
const sessionMacKey = deriveSessionMacKey(masterKey);

const storage = await createStorageBackend({
  type: 'postgres',
  connectionString: process.env.DATABASE_URL!,
  sessionMacKey,
});
await storage.initialize(); // initial controlled schema setup only; not safe as a repeatable boot runner

const scope = await AgentScope.create(
  { database: { connectionString: process.env.DATABASE_URL! } },
  { masterKey, storage },
);
```

`createStorageBackend` is the consumer-facing factory. Because lifecycle initialization and migration execution are coupled, direct consumers cannot start revocation coherency polling without also restarting the migration sequence. This is a current runtime limitation, not apply-once migration tracking.

The session-MAC key is required to construct a durable session store. `AgentScope` receives the umbrella `StorageBackend` but its public identity and query flows do not call `storage.sessions`; server or consumer orchestration owns session persistence. See [Security and Storage Boundaries](../guides/security-and-storage-boundaries.md#sessions-and-pending-oidc-flows) for the ownership distinction.

For test-only overrides of a composed backend, pass the required session-MAC key to the base backend:

```ts
import { composeStorageBackend, createStorageBackend, deriveSessionMacKey, InMemoryRevocationStore } from '@abaxxlabs/agents';

const sessionMacKey = deriveSessionMacKey(masterKey);
const base = await createStorageBackend({
  type: 'postgres',
  connectionString: process.env.DATABASE_URL!,
  sessionMacKey,
});
await base.initialize(); // initial controlled schema setup only

const storage = composeStorageBackend(base, {
  revocation: new InMemoryRevocationStore(), // tests only — do NOT use in production
});

const scope = await AgentScope.create(config, { masterKey, storage });
```

`composeStorageBackend` does NOT chain `.initialize()` across backends. The caller is responsible for controlled initialization of each sub-store before passing it in.

---

## Lessons from an in-repo migration dry run

The most complex in-repo consumer was used as the migration dry run for this release. Six call sites wrote `process.env.AGENTS_MASTER_KEY` as a control channel for per-session and per-org key switching. Findings that informed this guide:

- **Validate migration scope against current code.** Specifications can become outdated as call sites change. Confirm the current key-read and key-write locations before estimating each application's migration work.
- **Environment-based key switching requires additional migration work.** The consumer changed environment values at runtime to switch keys between organizations. Each request used the most recently assigned value. Migrating this pattern required tracing each write to its corresponding read and replacing both with explicit `Buffer` arguments to `AgentScope.create`. Allow additional migration time for environment writes after startup or environment reads in request-handling code.
- **Use compiler errors to identify outdated call sites.** Removing `AgentScopeConfig.encryption.masterKey` from the type causes remaining references to fail compilation. Resolve each reported call site using the applicable migration example.
- **Restrict placeholder keys to test fixtures.** An all-zero value such as `'00'.repeat(32)` passes `parseMasterKeyHex` but must not be used with real consumer data. Review these values during migration and remove them from production code paths or place them behind an explicit `NODE_ENV !== 'production'` gate.

---

## After the migration

1. **Verify the application boots cleanly.** The first boot under v0.9.10.0 with the same key value should be silent (no warnings, no errors). A `MasterKeyMismatchError` on first boot means the key value you threaded into `injections.masterKey` does not match what was wrapping your column keys at rest. Recover the correct value (almost always: re-check the env-vs-config audit from above) before continuing.
2. **Verify revocation enforcement.** If you operate multi-instance, revoke a test JTI on instance A and immediately verify it on instance B. Pre-v0.9.10.0 this would have silently passed verification. Post-v0.9.10.0 with `PostgresRevocationStore` injected, it should reject within `pollIntervalMs` (default 30s). If it does not reject, your revocation store injection is not wired correctly — re-read the [revocation-store injection](#revocation-store-injection-required-for-multi-instance) section.
3. **Lint cleanup (library scope).** The library ships ESLint trust-boundary rules for library core (`src/**/*.ts`, excluding bootstrap and CLI boundaries). Consumer projects do NOT inherit these rules automatically — they apply to library development, not your codebase. If you want the same protection in your consumer code, copy the relevant `no-restricted-syntax` selectors from the library's `eslint.config.ts` into your own ESLint configuration. The rules shipped as `warn` in v0.9.10.0 and are now enforced as `error`.
4. **Update documentation.** README, `.env.example`, deployment templates, and any internal docs that referenced the old config-field pattern need to point at the new injection pattern.

---

## References

- **CHANGELOG entry**: `CHANGELOG.md` § `[0.9.10.0]`.
- **Rollback procedure**: [v0.9.10.0 rollback guide](v0.9.10-rollback.md).
- **API surface**:
  - `AgentScope.create(config, injections)` — `src/sql/index.ts`
  - `AgentScopeInjections` interface — `src/sql/types.ts`
  - `MasterKey` branded type, `asMasterKey(buf)` — `src/crypto/master-key.ts`
  - `resolveMasterKeyFromEnv()`, `parseMasterKeyHex(hex)` — `src/bootstrap/index.ts`
  - `rewrapColumnKey({ pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey })` — `src/sql/column-keys.ts`
  - `composeStorageBackend(base, overrides)` — `src/storage/compose.ts`
- **Diagnostic CLI**: `npx @abaxxlabs/agents migrate-check` (read-only codebase scanner).
