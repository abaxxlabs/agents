# Migration: BYOK master key + injections boundary (v0.9.10.0)

**Audience:** anyone upgrading `@abaxxlabs/agents` from v0.9.6.0–v0.9.9.x to v0.9.10.0.
**Why this document exists:** v0.9.10.0 is a breaking change with two distinct axes:

1. **API shape**: `AgentScope.create(config, injections)` is now a two-parameter factory. The master key moves from `config.encryption.masterKey` (a hex string) to `injections.masterKey` (a 32-byte branded `MasterKey` Buffer). This is the BYOK ("bring your own key") boundary — the library no longer reads `AGENTS_MASTER_KEY` from the environment; consumers thread the key in.
2. **Revocation enforcement** (drift correction). Pre-v0.9.10.0, the `IRevocationStore` interface and three adapters shipped, but `AgentScope.create` had no way to receive an injected store. Every deployment ran on `InMemoryRevocationStore` regardless of what the JSDoc claimed. Multi-instance and durability-sensitive deployments were silently enforcing revocation only inside one process lifetime. This release wires the injection path and structurally prevents recurrence.

You read this doc top-to-bottom on first migration. On subsequent migrations of additional consumer projects, jump straight to the **decision tree** to find the relevant worked example.

---

## TL;DR

If you are running `@abaxxlabs/agents` today and you read `AGENTS_MASTER_KEY` from the environment, the smallest possible diff is:

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

Five questions. Answer them in order. Each leaf maps to one of the four worked examples plus any additional guidance.

| # | Question | Yes | No |
|---|---|---|---|
| Q1 | Do you read `AGENTS_MASTER_KEY` from `process.env` today? | go to Q3 | go to Q2 |
| Q2 | Do you set `encryption.masterKey` in `AgentScopeConfig` (config-file or inline) today? | go to Q3 | **case #1** (env-only / same-key, with no env reads — you must wire one up; see "If you currently have neither") |
| Q3 | Are you planning to **change the key value** as part of this upgrade (KMS migration, key rotation, fresh key)? | go to Q4 | go to Q5 |
| Q4 | Do you also want to move the key source off env vars (HSM / KMS / Secrets Manager) as part of this work? | **case #4** (new-key-with-rewrap + KMS sourcing) | **case #4** (new-key-with-rewrap, env-sourced) |
| Q5 | Do you have **both** env reads AND `encryption.masterKey` set in config today? | **environment audit first** — env was silently winning, audit which key value is yours; then you are case #1 or case #2 | go to Q6 |
| Q6 | Do you set `encryption.masterKey` in `AgentScopeConfig`? | **case #3** (config-hex / same-key) | **case #1** (env-only / same-key) |

Each case below stands alone — read only the one that applies.

If you are in **case #4**, also read the [`rewrapColumnKey` migration protocol](#rewrapcolumnkey-migration-protocol) section. It is not a one-liner.

If you operate **multi-instance** or rely on **cross-restart revocation durability**, also read the [revocation-store injection](#revocation-store-injection-required-for-multi-instance) section regardless of which case you are in.

---

## Environment audit (do this first)

Before applying any worked example, audit the actual key material your codebase references. v0.9.6.0–v0.9.9.x had a subtle "env was silently winning" trap: if a consumer set both `process.env.AGENTS_MASTER_KEY` AND `config.encryption.masterKey`, the env var won and the config field was ignored. Post-v0.9.10.0, only what you pass into `injections.masterKey` is the key — so if you copy from the wrong source, you get a wrong-key boot.

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

**This is the silently-winning trap.** Pre-v0.9.10.0 your env var was authoritative; the config field was dead code. Before you migrate, decide which value is the one you actually run with:

1. In a deployment shell, print **just the length** of the env var (never the value):
   ```bash
   node -e "console.log(process.env.AGENTS_MASTER_KEY?.length ?? 'unset')"
   ```
2. Compare against the config field's length. If they match in length but you are unsure they match byte-for-byte, treat the **env var** as canonical (that is what was actually wrapping your column keys) and discard the config field.
3. If they do not match in length, **stop**. Migrating with the wrong key will corrupt every encrypted column on first boot. Recover the env-var value from your secret manager, your `.env` history, or your deployment template — that is your live key. The config field was never the live key.

Once you have the canonical key value identified, proceed to the worked example matching your starting state.

### Step 3 — automate it (optional)

Run the diagnostic CLI to get a categorized report instead of eyeballing grep output:

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

- `resolveMasterKeyFromEnv()` is the new sanctioned site for reading `AGENTS_MASTER_KEY`. Do not read it again later — thread the resulting `MasterKey` (which is a `Buffer` at runtime) through your application as a normal value.
- Strict 64-hex-char validation happens at this boundary. A truncated, padded, base64, or whitespace-contaminated env var throws an explicit error here, not silently as a wrong-key boot inside the library.
- If you also call `deriveSessionMacKey(...)` in your bootstrap (server consumers), pass the same `masterKey` Buffer to it. Do not call `resolveMasterKeyFromEnv()` twice.

### If you currently have neither (no env read, no config write)

You were running with an undefined master key. Pre-v0.9.10.0 this either crashed at the first encrypt operation or worked accidentally because no encrypted columns were registered. v0.9.10.0 fails fast at construction (`MasterKeyMissingError`). Generate a key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Set it in your environment (`AGENTS_MASTER_KEY=<the hex>`) and follow case #1 above. Save the value — losing it bricks every encrypted column.

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

- `AgentScopeConfig.encryption.masterKey` is no longer a valid type. TypeScript will fail to compile if you leave it on a config object passed to `AgentScope.create`. The runtime ignores extra properties so you get a type error, not a silent runtime divergence — fix the type error and you are migrated.
- If your config file format includes the master key as a string field (YAML / JSON / TOML), you do not have to remove it from the file. Strip it at the consumer boundary right before calling `AgentScope.create`. The library never sees it.
- If you eventually move to KMS, `parseMasterKeyHex` is the helper you keep — it accepts a hex string from any source. KMS APIs that return raw bytes go through `asMasterKey(buf)` instead (see case #4).

---

## Case #3 — env-only, NEW key (rotating, moving to KMS, fresh credential)

**You are here if:** you read `AGENTS_MASTER_KEY` from env today, and you are changing the key value at the same time as the upgrade.

**Stop.** Do not migrate the API shape and rotate the key in one step. Master-key rotation requires re-wrapping every encrypted column key under the new master key — the library cannot guess the old key from the new one. If you ship a new env value with no rewrap, the library boots, fails to unwrap any column key under the new master, and throws `MasterKeyMismatchError`. Your application is down.

The correct sequence:

1. **First, complete case #1 with the OLD key.** Get to v0.9.10.0 on your existing key. Verify the application boots and decrypts column data. Commit and deploy.
2. **Then run the rewrap migration** to move from old key to new key. See [the `rewrapColumnKey` migration protocol](#rewrapcolumnkey-migration-protocol) below.
3. **Then update the env var (or move to KMS) in your bootstrap.**

If your operational reality is "we cannot deploy twice" (e.g. you discovered the key is compromised and you need to rotate now), you can do steps 1-3 inside a single maintenance window, but you still execute them as three sequential phases against a quiesced application — not as a single deploy.

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

Re-wrapping a column key under a new master key is a five-step, write-quiesced procedure. The library exposes the primitive (`rewrapColumnKey`) but does not run the protocol — write quiescence is a deployment concern, not a library concern.

**Why quiesce writes:** during the rewrap window, the `agent_keys` row for a column is locked (`SELECT ... FOR UPDATE`). New writes against the encrypted column would block on the lock, but more importantly: if you concurrently rotate AND rewrap the same column, the wrapped key swap order matters and you want the system idle while you do this work.

### The five steps

1. **Quiesce writes** to encrypted columns. Maintenance flag, read-only mode, advisory lock at the application layer, queue pause — your choice. Reads during this window are fine; writes against the encrypted columns must stop.
2. **Snapshot** `agent_keys` (mandatory). The wrapped-key bytes and the `agent_did` / `table_name` / `column_name` triple are the only authoritative record of which column-key wraps which column. A failed rewrap mid-pass is recoverable from snapshot; a failure with no snapshot is not.
   ```bash
   psql "$DATABASE_URL" -c "\\copy (SELECT * FROM agent_keys) TO 'agent_keys_pre_rewrap_$(date +%Y%m%d_%H%M).csv' CSV HEADER"
   ```
3. **Verify-old.** Confirm the OLD master key actually unwraps every column key listed in `agent_keys`. If any unwrap fails here, your pre-rewrap state is already broken — stop and recover before proceeding.
   ```ts
   import { verifyAllColumnKeys } from '@abaxxlabs/agents';
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
   import { rewrapColumnKey } from '@abaxxlabs/agents';
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
   Each call is its own transaction — `SELECT ... FOR UPDATE` on the `agent_keys` row, `unwrapColumnKey(oldMasterKey, ...)`, `wrapColumnKey(newMasterKey, ...)`, `UPDATE agent_keys SET encrypted_key = ...`, audit append, commit. If any single call throws, that row is unchanged. The remaining rows are still on the OLD key. The system is in a mixed state and that is OK as long as you do not let the application boot under the new master while mixed.
5. **Verify-new.** Confirm the NEW master key now unwraps every column key. If any row still unwraps under the OLD key, you missed it in step 4 — re-run the rewrap loop or call `rewrapColumnKey` manually for that row. Do not advance to step 6 until verify-new is 100% green.
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
6. **Cutover.** Update the bootstrap to source the NEW master key. Restart all instances. Resume writes. Done.

### Failure modes

- **`KeyRotationFailedError` thrown mid-step-4 with `phase: 'unwrap-old-key'`**: the OLD master key in your hand does not match what was actually wrapping the column key in `agent_keys`. Either the env-was-silently-winning audit was wrong, or someone rotated this column out-of-band since your snapshot. Compare with the pre-rewrap CSV.
- **`KeyRotationFailedError` with `phase: 'wrap-new-key'`**: the NEW master key failed length validation. Check `asMasterKey` is being called with a 32-byte Buffer.
- **`KeyRotationFailedError` with `phase: 'update-agent-keys'`**: a database write failure. Almost always transient (network blip, deadlock with concurrent writers — the latter shouldn't happen if you quiesced). Re-run the loop; rows already rewrapped are idempotent in the sense that running rewrap again on an already-new-key row will fail at `phase: 'unwrap-old-key'` — which is the correct safety behavior, not data loss.
- **System half-rewrapped at end of window**: rows with the new key are unreadable under the old master key, rows with the old key are unreadable under the new master key. **You cannot serve traffic in this state.** Either complete the rewrap loop on the remaining rows (preferred) OR roll back the rows you already rewrapped using the snapshot from step 2. Decide based on which is faster and which carries less risk. Do not improvise.

### What this protocol is NOT

- **Not online.** v0.9.10.0 does not support a dual-key transition window where the same column simultaneously accepts old-key and new-key reads. That is a future feature requiring a `generation` column on `agent_keys` and dual-key crypto plumbing. For now, the rewrap window is a maintenance window.
- **Not cross-application.** If multiple applications share the same Postgres database and the same encrypted columns (atypical but possible), all of them must restart against the new master key in the same window. Otherwise the application that is still on the old master will throw `MasterKeyMismatchError` on first decrypt.
- **Not partial.** Do not rewrap "the important columns" and leave the rest. The library expects a single master key per process. A column-by-column phased migration requires per-column master-key isolation, which the v0.9.10.0 surface does not expose.

---

## MAC-key co-rotation note (server consumers only)

This concerns deployments that use `packages/server/` and persist sessions via `PostgresSessionStore` or `SqliteSessionStore` (Session 5, v0.9.8.0+).

The session-envelope MAC key is HKDF-derived from the master key (`HKDF_CONTEXT_SESSION_MAC` context string). Changing the master key changes the MAC key. Any session envelope written under the OLD master key has a MAC tag derived from the OLD MAC key — and will fail integrity verification when re-read under the NEW master key.

**This is not a bug.** Sessions are short-lived (default 4h TTL) and the failed-integrity path is well-defined: the request is rejected with `401 SESSION_INTEGRITY_FAILED` and the user re-authenticates. The session table still has the row; it is just dead-on-read.

**Operational implication during BYOK rotation:** at the moment you cut over to the new master key, every existing session in the durable store becomes unreadable. Your users re-authenticate. Plan for it:

- **Single-instance deployments**: a brief auth blip at restart. Most users will not notice unless they are mid-flow.
- **Multi-instance deployments with sticky sessions**: same as single-instance — sticky sessions die with their instance during the rolling restart anyway.
- **Multi-instance deployments without sticky sessions, expecting cross-instance rehydrate**: the rehydrate path returns 401 for every pre-cutover envelope. Users re-auth. If this is unacceptable, schedule the BYOK cutover during low-traffic hours or behind a scheduled maintenance window.

There is no MAC-key versioning in v0.9.10.0. Sessions written before the cutover and sessions written after live under different MAC keys with no way for the new instance to verify the old envelopes.

You can pre-clear the session table at cutover time to avoid users getting 401s on stale envelopes:

```sql
-- Run in the maintenance window, before resuming traffic on the new master key.
DELETE FROM sessions;
```

This is optional — leaving the rows lets `pruneExpired` clean them up at TTL — but explicit deletion makes the post-cutover state cleaner.

---

## Revocation-store injection (required for multi-instance)

Whether your migration case is #1, #2, #3, or #4, a separate decision applies if you operate **multi-instance** OR rely on **revocation durability across process restarts**: you must inject a durable `IRevocationStore`. The default behavior when `injections.storage` is omitted is:

- `packages/server/` consumer: auto-detects a default `PostgresRevocationStore` when `DATABASE_URL` is set (and runs migration 007 idempotently on boot). Single INFO log line on startup names the active store. No code change needed.
- Direct library consumer: `AgentScope.create` constructs a default `PostgresStorageBackend` from `config.database.connectionString`, but **does not call `.initialize()` on it**. Three concrete consequences:
  - The revocation cache starts cold (first hits round-trip to Postgres).
  - Cross-instance coherency polling never starts — peer-instance revocations are seen only on cache miss.
  - **If migration 007 has not been applied yet (the `revoked_credentials` table does not exist), every `isRevoked` call throws `relation "revoked_credentials" does not exist`** and propagates through `VcVerifier.verify` to the caller. This is correct fail-loud behavior post-Session-6 (matches the wrong-key-boot posture), but consumers who haven't run migrations will see verification errors on the first credential check.

  This default-backend behavior is correct for tests and demos with pre-applied schemas; it is **not** sufficient for production multi-instance, and it is **not** safe for consumers who run AgentScope before applying schema migrations. Production deployments should explicitly construct + initialize the StorageBackend (see the wiring example below).

For production multi-instance, pre-build the StorageBackend so migration 007 (and 008 for sessions) apply on boot and the revocation cache warms before traffic arrives:

```ts
import { AgentScope, createStorageBackend } from '@abaxxlabs/agents';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();

const storage = await createStorageBackend({
  type: 'postgres',
  connectionString: process.env.DATABASE_URL!,
});
await storage.initialize(); // applies revocation/session migrations idempotently, warms cache, starts coherency poll

const scope = await AgentScope.create(
  { database: { connectionString: process.env.DATABASE_URL! } },
  { masterKey, storage },
);
```

`createStorageBackend` is the consumer-facing factory. It is sufficient for revocation durability, agent persistence, and audit. **If you also persist sessions and need MAC integrity across processes**, the session-MAC derivation pathway is non-trivial — read `packages/server/src/index.ts` (search for `deriveSessionMacKey`) for the canonical wiring. The package thread-loads the master key once via `resolveMasterKeyFromEnv()`, derives the session MAC key, and passes both the master key and the StorageBackend (constructed via `PostgresStorageBackend.fromPool` with the derived MAC key) into `AgentScope.create`.

For mixed-backend setups (Postgres for agents/audit/context, Redis for revocation, SQLite for sessions in dev), use `composeStorageBackend(base, overrides)`:

```ts
import { composeStorageBackend, createStorageBackend, InMemoryRevocationStore } from '@abaxxlabs/agents';

const base = await createStorageBackend({ type: 'postgres', connectionString: process.env.DATABASE_URL! });
await base.initialize();

const storage = composeStorageBackend(base, {
  revocation: new InMemoryRevocationStore(), // tests only — do NOT use in production
});

const scope = await AgentScope.create(config, { masterKey, storage });
```

`composeStorageBackend` does NOT chain `.initialize()` across backends. The caller is responsible for initializing each sub-store before passing it in.

---

## Lessons from migrating the showcase (in-repo dry run)

The `demo/showcase/` consumer was used as the migration dry-run for this release. It was the most complex consumer in the repository — six call sites that wrote `process.env.AGENTS_MASTER_KEY` as a control channel for per-session and per-org key switching. Findings that informed this guide:

- **Plan-doc counts can be stale.** The original spec described "9 env-write sites in the showcase" but the actual count at migration time was 6 — Lane B's earlier work had already removed some. **Verify against current code, not plan-doc claims**, before scoping each consumer's migration.
- **Env-as-control-channel is the worst pattern to migrate.** The showcase used env writes to switch keys mid-process between organizations. Every read site read the env at request time, so the implicit invariant was "whatever the most recent write was." Untangling this required tracing each write to its corresponding read and replacing both with explicit `Buffer` arguments to `AgentScope.create`. If your consumer has any pattern resembling this — env writes after startup, env reads inside hot paths — budget more time.
- **Type errors are your friend.** Once `AgentScopeConfig.encryption.masterKey` is removed at the type level, every stale call site fails to compile. Walk the type errors top-to-bottom; each is a structurally identical fix.
- **Dev keys with all-zero hex are a smell.** `'00'.repeat(32)` was a fixture pattern. It is technically valid (passes `parseMasterKeyHex`) but it should never appear in any code path that runs against real consumer data. The migration is a good moment to grep for it and either delete or move it explicitly behind a `NODE_ENV !== 'production'` gate.

---

## After the migration

1. **Verify the application boots cleanly.** The first boot under v0.9.10.0 with the same key value should be silent (no warnings, no errors). A `MasterKeyMismatchError` on first boot means the key value you threaded into `injections.masterKey` does not match what was wrapping your column keys at rest. Recover the correct value (almost always: re-check the env-vs-config audit from above) before continuing.
2. **Verify revocation enforcement.** If you operate multi-instance, revoke a test JTI on instance A and immediately verify it on instance B. Pre-v0.9.10.0 this would have silently passed verification. Post-v0.9.10.0 with `PostgresRevocationStore` injected, it should reject within `pollIntervalMs` (default 30s). If it does not reject, your revocation store injection is not wired correctly — re-read the [revocation-store injection](#revocation-store-injection-required-for-multi-instance) section.
3. **Lint cleanup (library scope).** The library ships ESLint trust-boundary rules that fire inside `src/**/*.ts` and `packages/server/src/**/*.ts` only. Consumer projects do NOT inherit these rules automatically — they apply to library development, not your codebase. If you want the same protection in your consumer code, copy the relevant `no-restricted-syntax` selectors from the library's `eslint.config.js` into your own ESLint configuration. The rules are `warn` in v0.9.10.0; they will be promoted to `error` in a future library release.
4. **Rotate documentation.** README, `.env.example`, deployment templates, and any internal docs that referenced the old config-field pattern need to point at the new injection pattern.

---

## References

- **CHANGELOG entry**: `CHANGELOG.md` § `[0.9.10.0]`.
- **Rollback procedure**: `docs/rollback-v0.9.10.0.md`.
- **API surface**:
  - `AgentScope.create(config, injections)` — `src/sql/index.ts`
  - `AgentScopeInjections` interface — `src/sql/types.ts`
  - `MasterKey` branded type, `asMasterKey(buf)` — `src/crypto/master-key.ts`
  - `resolveMasterKeyFromEnv()`, `parseMasterKeyHex(hex)` — `src/bootstrap/index.ts`
  - `rewrapColumnKey({ pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey })` — `src/column-encryption.ts`
  - `composeStorageBackend(base, overrides)` — `src/storage/compose.ts`
- **Diagnostic CLI**: `npx @abaxxlabs/agents migrate-check` (read-only codebase scanner).
- **Issue / discussion**: Jira `ABXAGNTS-189` (BYOK), `ABXAGNTS-180` (revocation enforcement).
