# Support Runbook — v0.9.10.0

**Version:** v0.9.10.0
**Audience:** On-call engineer, SRE, support team
**Scope:** Operational diagnostics for issues introduced or affected by v0.9.10.0 — the BYOK injection boundary and the revocation enforcement drift correction.

This runbook covers what is **new or changed** in v0.9.10.0. For ongoing operations on infrastructure that pre-existed this release (Postgres revocation store CRUD, session store administration, audit chain queries), see the prior runbooks listed under §"Related runbooks" at the bottom.

---

## Section 1 — Revocation Enforcement (new in v0.9.10.0)

### Background

Versions v0.9.6.0 through v0.9.9.x advertised an injection path for `IRevocationStore` that no code implemented. The `IRevocationStore` interface and three adapters (`InMemoryRevocationStore`, `SqliteRevocationStore`, `PostgresRevocationStore`) shipped in v0.9.6.0, but `AgentScope.create` had no parameter to receive an injected store — the `VcVerifier` silently defaulted to `InMemoryRevocationStore` in every deployment.

The practical consequence: **multi-instance deployments were enforcing revocation only within a single process lifetime**. A revocation written on instance A was invisible to instance B, and neither instance survived a process restart. This was the drift class corrected in v0.9.10.0.

After v0.9.10.0, `AgentScope.create` requires the injection path; `packages/server/` auto-detects the right backend; and the `VcVerifier` type signature now refuses to be constructed without a `revocationStore`.

### Diagnostic 1.1 — "Which revocation store am I actually running?"

This is the question every operator wants to answer right after the v0.9.10.0 deploy. Three independent signals:

#### Signal A — Startup log line

`packages/server/` emits exactly one INFO log line at startup naming the active store and the durability claim. Example:

```
[agents-server] revocation store: postgres (durable, cross-instance coherent)
```

Possible values:
- `postgres (durable, cross-instance coherent)` — `PostgresRevocationStore` selected. This is the production-correct state for any multi-instance deployment.
- `sqlite (durable, single-process)` — `SqliteRevocationStore` selected. Correct for single-process consumers (Chief, local development); wrong for multi-instance.
- `memory (process-local, lost on restart)` — `InMemoryRevocationStore` selected. **NOT correct for production multi-instance.** Either `DATABASE_URL` is unset, or `REVOCATION_STORE=memory` was explicitly set.

```bash
# Find the line in your aggregator (kubectl, journalctl, CloudWatch, etc.)
kubectl logs -l app=agents-server --tail=200 | grep "revocation store:"
```

If the log line is missing, the server may be running a pre-v0.9.10.0 build. Check the package version:

```bash
kubectl exec deploy/agents-server -- npm ls @abaxxtech/agents | grep agents
# Expected: @abaxxtech/agents@0.9.10.0 or higher
```

#### Signal B — Direct introspection (for library consumers)

Library consumers who construct `AgentScope` manually can introspect the active store by checking the type of the storage backend they passed:

```ts
const storage = await createStorageBackend({ type: 'postgres', connectionString });
console.log('[ops] revocation store:', storage.revocation.constructor.name);
// Expected: 'PostgresRevocationStore' | 'SqliteRevocationStore' | 'InMemoryRevocationStore'
```

If this prints `InMemoryRevocationStore` against a Postgres connection string, the StorageBackend assembly is wrong — review the bootstrap.

#### Signal C — Live revocation propagation test

The definitive test. Revoke a credential JTI on instance A's database and verify the cache on instance B picks it up within the poll window. The server's `DELETE /credentials/:id` endpoint requires the session that issued the credential, so it is awkward for ops use; the SQL path is the operator-friendly equivalent.

```bash
# Pick any non-production JTI (a test credential, an expired credential, or
# manufacture a synthetic one — the test only proves cache propagation).
JTI="propagation-test-$(date +%s)"

# 1. Insert directly into the table (instance A's database).
psql "$DATABASE_URL" -c "
  INSERT INTO revoked_credentials (jti, expires_at)
  VALUES ('$JTI', NOW() + INTERVAL '1 hour')
  ON CONFLICT (jti) DO NOTHING;
"

# 2. Wait the poll interval plus a safety margin.
sleep 35

# 3. Verify the JTI appears in both instances' isRevoked() check. The
# library does not expose a public "is this JTI revoked?" probe at the
# HTTP layer, so the cleanest test is to inspect the cache via a debug
# endpoint or attempt a verification that uses the JTI.
#
# Pragmatic shortcut: tail server logs and watch for an authentic
# verification attempt that produces a "revoked" audit entry on each
# instance:
kubectl logs -l app=agents-server --tail=100 | grep -E "revoked|isRevoked"

# 4. Cleanup
psql "$DATABASE_URL" -c "DELETE FROM revoked_credentials WHERE jti = '$JTI';"
```

If instance B does not see the revocation within the poll interval, drop to Section 1.3 — Common failure modes.

Note: out-of-band SQL inserts skip the per-instance synchronous cache invalidation that the in-process `revoke()` call provides. The poll cycle catches them, but cross-instance latency is bounded by `pollIntervalMs + NEGATIVE_CACHE_TTL_MS`. For routine revocations, prefer `DELETE /credentials/:id` from the issuing session — it invalidates the local cache synchronously.

### Diagnostic 1.2 — Post-upgrade smoke test

Run this checklist within the first hour of a v0.9.10.0 deploy:

| Check | Command | Expected |
|---|---|---|
| Package version | `npm ls @abaxxtech/agents` | `0.9.10.0` (or patch above) |
| Boot is clean | grep server logs for `MasterKeyMissingError\|MasterKeyMismatchError` | no hits |
| Active revocation store | grep server logs for `revocation store:` | `postgres (durable, ...)` for multi-instance |
| Migration 007 applied | `\d revoked_credentials` in psql | table exists with expected columns |
| Live revocation propagation | Diagnostic 1.1 Signal C | 401 on instance B |

### Diagnostic 1.3 — Common failure modes

#### "Revocation not enforced after deploy"

Most likely cause: `REVOCATION_STORE=memory` was explicitly set, overriding the auto-detection. Check env on each instance:

```bash
kubectl exec deploy/agents-server -- env | grep REVOCATION_STORE
# Expected (auto-detect): unset, OR REVOCATION_STORE=auto
# Wrong for production: REVOCATION_STORE=memory
```

If the deploy template was carried forward from a pre-v0.9.10.0 staging configuration, the `REVOCATION_STORE=memory` line may have stuck for the wrong reasons. Remove it; restart.

#### "Revocations work on instance A, not B"

See Diagnostic 1.1 Signal C. If propagation is failing AND both instances log `postgres (durable, ...)`, the cause is one of:

- **Read replica routing.** If your connection string routes to a read replica, revocation reads are stale by replication lag. Direct the revocation pool to the primary (`target_session_attrs=read-write` or a separate primary URL).
- **Poll interval too long.** Default 30s. The interval is currently a library-level option (`PostgresRevocationStore` constructor `pollIntervalMs`) — `packages/server/` does not expose an env-var pass-through in v0.9.10.0. Consumers who need a tighter window must construct the StorageBackend explicitly and pass the option through.
- **Connection pool saturation.** Poll cycle silently failing. Check Postgres `pg_stat_activity` and `max_connections`. See the prior session-3 runbook for the full pool-saturation playbook.

#### "Revocations lost after restart"

Indicates `InMemoryRevocationStore` is the active backend (memory-only persistence). See Diagnostic 1.1 Signal A — the startup log line will show `memory (process-local, lost on restart)`. Either set `DATABASE_URL` (auto-detect picks Postgres) or explicitly set `REVOCATION_STORE=postgres`.

#### "Out-of-band SQL revocation not visible"

If an operator inserts a row directly into `revoked_credentials` (e.g. emergency mass revoke during an incident), the in-process cache will not see it for up to `pollIntervalMs`. To force immediate visibility, restart the server (cold-cache reload via `loadAll()` runs on `initialize()`).

For planned out-of-band operations, prefer the admin HTTP endpoint — it goes through `revoke()` which invalidates the local cache synchronously and the cross-instance caches via the next poll.

### Admin operations

#### Mass revoke

```sql
-- Revoke all credentials issued before a cutoff (incident response).
-- agent_audit holds credential_id but not the credential's exp claim, so
-- we insert with expires_at = NULL. Non-expiring revocations are never
-- auto-pruned — clean them up manually after the incident is contained
-- (see "Manual prune" below).
INSERT INTO revoked_credentials (jti, reason)
SELECT DISTINCT credential_id, 'incident-mass-revoke'
FROM agent_audit
WHERE timestamp < $1 AND credential_id IS NOT NULL
ON CONFLICT (jti) DO NOTHING;
```

Restart all instances afterward to force cache reload (the poll cycle will catch them anyway, but a restart makes the boundary observable).

#### Manual prune

```sql
-- Background prune is daily; manual prune for emergency cleanup.
DELETE FROM revoked_credentials
WHERE expires_at IS NOT NULL
  AND expires_at < NOW() - INTERVAL '30 days';
```

The 30-day post-expiry retention is the cross-instance cache safety margin (caches must evict before the DB row disappears). Do not shorten it without coordination.

#### Audit query — "what was revoked when?"

```sql
SELECT jti, reason, revoked_at, expires_at
FROM revoked_credentials
ORDER BY revoked_at DESC
LIMIT 50;
```

(The `revoked_credentials` schema does not record the revoking actor — that signal lives in `agent_audit` against the `credential_id` of the revoked JTI. Cross-reference with `SELECT * FROM agent_audit WHERE credential_id = '<jti>' AND status = 'revoked'`.)

For full audit-chain queries, see the prior session-3 runbook.

---

## Section 2 — BYOK boot diagnostics (new in v0.9.10.0)

### Background

v0.9.10.0 changes how the master key reaches the library. Pre-v0.9.10.0, the library read `AGENTS_MASTER_KEY` from the environment and / or `config.encryption.masterKey` from the config object. Post-v0.9.10.0, the library never reads the env; `injections.masterKey: MasterKey` is the only path. Wrong-key boots that previously degraded silently (with `[ENCRYPTED]` placeholder reads) now fail loudly with `MasterKeyMismatchError`.

This is a deliberate posture change. Wrong-key boots are now audible — most v0.9.10.0 boot failures are real misconfigurations that would have been silent on the prior version.

### Diagnostic 2.1 — "MasterKeyMissingError on first boot"

```
MasterKeyMissingError: Master key not provided. Pass a 32-byte Buffer as
injections.masterKey to AgentScope.create(config, injections). For env-var
bootstrap, import parseMasterKeyHex from '@abaxxtech/agents/bootstrap'
(strict 64-hex validation). See docs/migration-byok.md for full examples.
```

The bootstrap code is missing the `injections.masterKey` argument or `injections` itself. Most common cause: the consumer upgraded the package version but did not update the call site. The TypeScript compiler should have caught this at build time; if the error is appearing at runtime, the consumer likely:

- Built against a pre-v0.9.10.0 type definition and bumped the runtime package only.
- Used `as any` or `// @ts-ignore` to silence the type error.
- Has a custom factory wrapping `AgentScope.create` that pre-dates the breaking change.

Direct the consumer to `docs/migration-byok.md` § "Case #1" for the canonical bootstrap shape.

### Diagnostic 2.2 — "MasterKeyMismatchError on first boot"

```
MasterKeyMismatchError: Column keys exist but cannot be decrypted with the
provided master key. Wrong key or corrupted data.
```

The `agent_keys` table is non-empty AND none of the wrapped column keys decode under the supplied master key. The library cannot tell whether this is a wrong key or actual data corruption — both produce the same crypto-level signal — so the error message names both possibilities.

Almost always: it is a wrong key.

#### Triage

1. **Was the master key value changed during the upgrade?** If yes, see `docs/migration-byok.md` § "Case #4" for the rewrap protocol. Rolling back the application without rotating the column keys back is the wrong move (see `docs/rollback-v0.9.10.0.md` § "Data-loss surface").
2. **Was the master key value the same but the SOURCE changed?** This is the "env was silently winning" trap residue. If pre-v0.9.10.0 the consumer had BOTH `process.env.AGENTS_MASTER_KEY` AND `config.encryption.masterKey` set, the env var was authoritative. If the v0.9.10.0 migration copied the value from the wrong source (the dead config field instead of the live env var), every wrapped key fails. Run the env audit from `docs/migration-byok.md` § "Environment audit" to identify the canonical value.
3. **Was the bootstrap source decoded incorrectly?** Pre-v0.9.10.0 the library accepted hex strings; v0.9.10.0 takes a Buffer. Check that the consumer is calling `parseMasterKeyHex(hex)` or `Buffer.from(hex, 'hex')` — NOT `Buffer.from(hex)` (which UTF-8-decodes and produces 64 bytes, not 32).
4. **Is the agents database the same one the prior deploy was using?** The most embarrassing root cause — the deploy is pointing at a different `DATABASE_URL` whose `agent_keys` table was wrapped under a different master key entirely. Compare the `connectionString` against the prior deployment's.

#### What this is NOT

- It is not "data corruption" in the sense of bytes flipping at rest. The crypto-level signal looks the same, but Postgres at-rest corruption of bytea columns is extremely rare. Default to "wrong key" until proven otherwise.

### Diagnostic 2.3 — "I want to confirm the library is no longer reading the env var directly"

The library (`src/`) does not read `AGENTS_MASTER_KEY` post-v0.9.10.0; the master key arrives only via `injections.masterKey`. ESLint rules in `src/**/*.ts` (lib core) statically enforce this — see `eslint.config.js` rules under `[BYOK D16]`. The sanctioned env-read site is `resolveMasterKeyFromEnv()` in `src/bootstrap/index.ts`, which only runs when a consumer explicitly imports it.

Verification, if you need to prove this to a security reviewer:

```bash
# Should return zero results (the consumer-boundary read site is in
# src/bootstrap/, not under src/ minus bootstrap and cli).
grep -rn "process.env.AGENTS_MASTER_KEY\|process\.env\[.AGENTS_MASTER_KEY" \
  src/ --exclude-dir=bootstrap --exclude-dir=cli | grep -v "^src/.*\.md\b"
```

Library consumers building from raw bytes (KMS, HSM, secrets manager) bypass the env path entirely; the master key arrives via `asMasterKey(buf)`.

### Admin operations

#### Mid-window key rotation diagnostic

If a master-key rotation was attempted during a v0.9.10.0 maintenance window and you are not sure how far it got, run `verifyAllColumnKeys` against both candidates:

```ts
import { verifyAllColumnKeys } from '@abaxxtech/agents';
import { parseMasterKeyHex } from '@abaxxtech/agents/bootstrap';

const oldKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_OLD!);
const newKey = parseMasterKeyHex(process.env.AGENTS_MASTER_KEY_NEW!);

console.log('under OLD key:', await verifyAllColumnKeys(pool, oldKey));
console.log('under NEW key:', await verifyAllColumnKeys(pool, newKey));
```

The two reports together pin down exactly which rows are wrapped under which key. From there:
- All under OLD → rotation never started. Either re-run or bail.
- All under NEW → rotation completed. Cut over.
- Split → mid-window state. See `docs/migration-byok.md` § "Failure modes — system half-rewrapped" before resuming.

---

## Section 3 — Audit chain integrity (unchanged but worth confirming)

v0.9.10.0 ships no audit-chain changes. The hash logic, the audit record version, and the `agent_audit` schema are identical to v0.9.9.0. Existing audit verification tooling (`agents verify`) works without modification across the upgrade.

If a customer reports audit-chain verification failures after v0.9.10.0, the cause is upstream of this release — chase it via the standard audit-chain runbook, not via this document.

---

## Escalation path

| Severity | Condition | Action |
|---|---|---|
| P0 | Revocations not being enforced (Diagnostic 1.1 Signal C fails) | Page on-call + escalate to Product Security immediately |
| P0 | Wrong-key boot in production with column data inaccessible | Page on-call; consult §"Data-loss surface" in `docs/rollback-v0.9.10.0.md` |
| P1 | `MasterKeyMissingError` blocking deploy | Walk the deployer through the Case #1 example in `docs/migration-byok.md` |
| P1 | Cross-instance revocation propagation failing | See Diagnostic 1.3; check pool, replication, poll interval |
| P2 | InMemoryRevocationStore active in single-process consumer (e.g. Chief) | Expected behavior; not a regression |
| P3 | Post-upgrade env-var lint warnings noisy | Treat as a punch list per `docs/migration-byok.md` § "After the migration" |

---

## Section 3.5 — MCP multi-instance revocation coherency (Session 7 / ABXAGNTS-250)

The MCP CLI (`src/mcp/index.ts`, the `agents mcp` command) calls `AgentScope.create` with no `injections.storage` argument. The library responds by building a default `PostgresStorageBackend` from `config.database.connectionString` — but with the cross-instance revocation **coherency poll deliberately OFF**. The trade-off is documented in the `AgentScopeInjections.storage` JSDoc (`src/sql/types.ts:61-70`); the full revocation poll option surface is in `src/storage/postgres/revocation-store.ts` (`PostgresRevocationStoreOptions`).

**What this means in practice:**

| Deployment shape | Impact | Recommendation |
|---|---|---|
| Single MCP instance | None — there's no peer to drift from. Revocations written locally are read locally. | Acceptable. The default-backend path is correct. |
| Multi-instance MCP behind a load balancer | A revocation written on instance A is invisible to instance B until B restarts. Cross-instance attackers can present a credential to a peer instance after revocation. | **NOT acceptable.** Construct an explicit `StorageBackend` with the coherency poll enabled and pass via `injections.storage`. |

### Detecting the trade-off at runtime

ABXAGNTS-250 added a startup warning that fires when:
- `NODE_ENV === 'production'`
- The MCP CLI is the bootstrap path (no consumer-side `injections.storage`)

The warning text:
> `WARNING: MCP server booting in NODE_ENV=production without an explicit storage injection.` ...

If you see this in production logs, decide between (a) accepting single-instance MCP and adding `MCP_INSTANCES=1` (or equivalent) to your deploy manifest as documentation, or (b) migrating to a custom bootstrap that constructs `StorageBackend` explicitly.

### Migrating to explicit storage in MCP

The MCP CLI does not currently take a `--storage` flag. Operators who need multi-instance MCP today have two options:

1. **Custom entry point**: write a small wrapper script that imports `startMcpServer` programmatically and constructs a `StorageBackend` (with `coherencyPoll: true`) before passing it to `AgentScope.create`. Reference: `packages/server/src/index.ts:1500+` for the API server's pattern, which already does this.
2. **Wait for native flag**: a future Session-8+ ticket may add `--injections-storage` to the MCP CLI. Track ABXAGNTS-243 for follow-up.

Either way, the warning surfaces the trade-off. Silent revocation drift in multi-instance MCP was the failure mode this ticket structurally guards against.

---

## Section 4 — Environment variables read by the library (Session 7 / ABXAGNTS-249)

The Session 7 library-shrink arc (v0.10.0) moved most env-reads out of the library proper and into the consumer-boundary `@abaxxtech/agents/bootstrap` subpath or explicit `AgentScopeConfig` fields. Two env vars are **intentionally retained** as library-implicit reads because they encode universal Node/CI runtime conventions, not deployment posture decisions. This section documents them so operators know what env affects library behavior without grepping the source.

### NODE_ENV — production-runtime gate (defense in depth)

**Read sites:**
- `src/index.ts` (mock auth gate inside `authenticate()`)
- `src/auth/agent.ts` (`createMockSession()` throws unless `NODE_ENV ∈ {development, test}`)
- `src/auth/discovery-utils.ts` (localhost OIDC discovery is allowed in non-prod, rejected as SSRF seed in prod)

**Why kept as library-implicit:** `NODE_ENV` is exposed by every Node runtime and explicitly set by every framework. Its semantics are universal: "I am, in fact, in a production runtime." The library uses it as a defense-in-depth security gate — even if a consumer passes `devMode: true` in `AgentScopeConfig` (Session 7 / ABXAGNTS-246), `NODE_ENV !== 'production'` is the runtime double-check that prevents mock-auth code paths from booting in production. The two layers are intentionally redundant: `devMode` says "I want dev defaults"; `NODE_ENV` says "I am, in fact, in a non-prod runtime."

**Operator implications:**
- In production, leave `NODE_ENV` unset OR explicitly `production`. Mock auth cannot boot either way.
- For dev demos, set `NODE_ENV=development` (or `test` for CI test runners). The library's mock-auth paths are then permitted.
- `packages/server/` defaults `NODE_ENV` to `production` if unset (line ~135 of `packages/server/src/index.ts`) — adversarial-review hardening to close a "forgot to set NODE_ENV" footgun.

**Drift-prevention:** the ESLint trust-boundary rules (D16) flag direct `process.env` reads inside `src/` outside the bootstrap/cli exempt paths. `NODE_ENV` is the one universal exception, documented in the rule's allow-list.

### CI — CI-aware keystore behavior (universal CI convention)

**Read sites:**
- `src/identity/keystore.ts` (`createKeystore()` — `CI=true` forces the `JsonFileBackend` even on macOS, skipping the Keychain prompt that would otherwise block CI runs)

**Why kept as library-implicit:** `CI=true` is set by every major CI provider (GitHub Actions, GitLab CI, CircleCI, Jenkins, Travis, Buildkite, etc.). The library reading it lets the keystore behave sensibly in CI without consumer intervention — the alternative would be every CI configuration forwarding an explicit `devMode: true` through the consumer, which is busywork for behavior that's already universally signaled.

**Operator implications:**
- In CI: `CI=true` is set automatically by the runner. The keystore selects `JsonFileBackend` unattended; no Keychain prompt blocks the build.
- In dev (macOS, no CI): the Keychain backend is selected; the user gets a one-time keychain prompt to authorize the agent.
- To force `JsonFileBackend` outside CI (e.g. in a Linux container running on macOS host), set `CI=true` OR pass `createKeystore({ devMode: true })`.

### What this is NOT

These two env vars are **runtime-shape gates**, not deployment posture decisions. They tell the library "what kind of runtime am I in?" not "what does the operator want me to do?" Posture decisions (master key source, trusted server DIDs, consumer-domain registry, scope mode) all moved to explicit `AgentScopeConfig` fields or `@abaxxtech/agents/bootstrap` helpers in v0.10.0. If you find yourself wanting to add a third env-read inside `src/`, push back hard — the v0.10.0 migration was specifically about ending that pattern.

### Drift-prevention reference

The ESLint rules at `eslint.config.ts` (and tested in `test/drift-prevention/eslint-rules.test.ts`) enforce that direct `process.env.AGENTS_*` reads do NOT appear inside `src/` outside the bootstrap and cli paths. `NODE_ENV` and `CI` are explicitly exempt because they are not part of the AGENTS_* prefix. Any Session-8+ work that removes the last AGENTS_* env-read should also tighten these rules from `warn` to `error`.

---

## Related runbooks

- **Postgres revocation store ops** (CRUD against `revoked_credentials`, pool tuning, replication, prune jobs): `demo/hackathon/findings/session-plans/session-3-release/runbook-postgres-revocation-store.md` — pre-existing from v0.9.6.0, still authoritative for ongoing operations.
- **Postgres session store ops** (`sessions` table, MAC integrity, prune): `demo/hackathon/findings/session-plans/session-5-release/runbook-postgres-session-store.md`.
- **Migration guide** (consumer-facing upgrade path): `docs/migration-byok.md`.
- **Rollback procedure**: `docs/rollback-v0.9.10.0.md`.
- **CHANGELOG**: `CHANGELOG.md` § `[0.9.10.0]` (Session 6) + `[Unreleased]` (Session 7).
