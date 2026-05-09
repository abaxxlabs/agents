# Rollback Procedure — v0.9.10.0 (BYOK + revocation enforcement)

**Version being rolled back:** v0.9.10.0
**Roll back to:** v0.9.9.0 (or any v0.9.6.x–v0.9.9.x)
**Scope:** application code + bootstrap config. **No DB schema rollback required.**

## When to roll back

Roll back if any of the following surface within the post-deploy validation window:

- **Wrong-key boots across the fleet.** `MasterKeyMismatchError` thrown on first contact with encrypted columns despite the migration audit reporting clean. Indicates a key-source mismatch between what was wrapping column keys at rest and what is being threaded into `injections.masterKey`.
- **Revocation enforcement regression.** A previously-working revocation flow starts silently passing. The type-level `revocationStore` required parameter on `VcVerifierOptions` should make this a near-impossible regression in v0.9.10.0 — but if it surfaces, treat it as a rollback trigger.
- **Operator-declared emergency.** Anything else that calls for "go back to the prior known-good state right now."

Routine bug reports that do not touch column-key access or revocation enforcement are typically better fixed in a follow-up patch than addressed via rollback.

## What rollback does

Reverts the application code to a v0.9.9.x package version and restores the prior bootstrap shape (`AgentScope.create(config)` with `config.encryption.masterKey`, OR with `process.env.AGENTS_MASTER_KEY` read inside the library). It does NOT touch any database schema or any data at rest.

| Concern | Behavior on rollback |
|---|---|
| `agent_keys` table | Untouched. Existing wrapped column keys remain valid. |
| `revoked_credentials` table (migration 007) | Untouched. Stays in place. v0.9.6.x–v0.9.9.x consumers run on the same table. |
| `sessions` table (migration 008) | Untouched. Pre-existing session envelopes remain. |
| `agent_audit` records | Untouched. The hash chain continues unbroken. |
| Encrypted column data | **Untouched, IF the master key was not rotated during the v0.9.10.0 upgrade window.** See §"Data-loss surface" below. |
| `injections.masterKey` API surface | Removed (back to v0.9.9.x's `config.encryption.masterKey`). Bootstrap code must be reverted. |

## Data-loss surface

The only data-loss risk is master-key rotation that completed during the v0.9.10.0 window. Specifically:

- **If you executed the `rewrapColumnKey` migration protocol** during the v0.9.10.0 deploy and your `agent_keys` rows are now wrapped under the NEW master key, rolling back the application code without rolling back the master key leaves the v0.9.9.x package booting with the OLD master key against NEW-key-wrapped columns. v0.9.9.x's `loadColumnKeys` will silently warn-and-continue (the legacy partial-success behavior pre-v0.9.10.0); encrypted columns will render as `[ENCRYPTED]` placeholders in scoped queries. **This is the silent-failure mode that v0.9.10.0's `MasterKeyMismatchError` was designed to make audible.**
- **If you did NOT rotate the master key** during the v0.9.10.0 upgrade, rollback is data-safe: column keys are still wrapped under the same master key your v0.9.9.x application supplies via `process.env.AGENTS_MASTER_KEY` or `config.encryption.masterKey`.

If you are in the rotated-and-need-to-roll-back state, you have two options:

1. **Rotate back.** Run `rewrapColumnKey` (still available in v0.9.9.0) against every row in `agent_keys`, swapping the NEW master key back to the OLD master key. Verify with the v0.9.9.0 `loadColumnKeys` warm-path before flipping the bootstrap source.
2. **Keep the new key.** Roll back the application code but bootstrap v0.9.9.x with the NEW master key (`AGENTS_MASTER_KEY` env var or `config.encryption.masterKey` field set to the new hex). Sessions written under the v0.9.10.0 MAC key will fail integrity verification on first re-read; users re-authenticate. Acceptable if the rotation was deliberate.

Pick option 1 if rotation was a security-incident response and you want to preserve the deliberate post-incident posture in your audit log. Pick option 2 if rotation was opportunistic ("we had to migrate anyway, so we rotated") and there is no operational reason to undo it.

## Procedure

### 1. Quiesce writes (recommended, not strictly required)

Flip your application into maintenance mode (or take the offending instances offline). Sessions issued during the rollback window will fail integrity verification when the new code re-reads them; quiescence avoids users seeing transient 401s mid-flow.

For multi-instance, drain one instance at a time if you can tolerate the staggered rollback; otherwise take the whole fleet offline for the duration.

### 2. Downgrade the package

```bash
# Pin to the last known-good version.
npm install --save-exact @abaxxlabs/agents@0.9.9.0

# OR via package-lock revert if you committed a known-good lockfile.
git checkout <pre-v0.9.10.0-commit> -- package.json package-lock.json
npm ci
```

If you also use `packages/server` from the same monorepo, downgrade or revert it together — the server's bootstrap reads the master key with the v0.9.10.0 BYOK pattern and will not boot against an older library version with the new helpers.

### 3. Revert the bootstrap shape

Restore the v0.9.9.x call shape. Two patterns work; pick the one that matches your pre-v0.9.10.0 state.

#### If you were on case #1 (env-only) pre-v0.9.10.0

```ts
// AFTER (v0.9.10.0): two-param factory + injections.masterKey
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
const masterKey = resolveMasterKeyFromEnv();
const scope = await AgentScope.create(config, { masterKey });

// REVERT TO (v0.9.9.x): single-param factory + env-read inside the library
const scope = await AgentScope.create({
  ...config,
  encryption: { ...config.encryption, masterKey: process.env.AGENTS_MASTER_KEY },
});
```

#### If you were on case #2 (config-hex) pre-v0.9.10.0

```ts
// AFTER (v0.9.10.0):
import { parseMasterKeyHex } from '@abaxxlabs/agents/bootstrap';
const masterKey = parseMasterKeyHex(config.encryption.masterKey);
const { masterKey: _, ...rest } = config.encryption;
const scope = await AgentScope.create({ ...config, encryption: rest }, { masterKey });

// REVERT TO (v0.9.9.x):
const scope = await AgentScope.create(config); // hex string passes straight through
```

If you are unsure which case you were on pre-v0.9.10.0, check git for the bootstrap call site immediately before the v0.9.10.0 migration commit. The migration doc's environment audit (`docs/migration-byok.md` § "Environment audit") is the same procedure inverted.

### 4. Restart

```bash
# Multi-instance: rolling restart.
# Single-instance: full restart.
```

Verify the application boots without `MasterKeyMissingError` or `MasterKeyMismatchError`.

### 5. Resume traffic

Drain traffic back to the rolled-back instances. Users authenticated against v0.9.10.0 will see 401s on their next request because the session-MAC key is derived from the master key with a v0.9.10.0 HKDF context string that v0.9.9.x does not produce. Users re-authenticate. This is the same behavior as the BYOK-key-rotation MAC-key co-rotation note in the migration doc.

## Verification

After rollback:

```bash
# Package version
npm ls @abaxxlabs/agents
# Expected: @abaxxlabs/agents@0.9.9.0 (or the chosen pre-v0.9.10.0 version)

# Application boot
# Expected: clean startup, no MasterKeyMissingError / MasterKeyMismatchError
```

```sql
-- Schema sanity (should be unchanged from before rollback)
\d agent_keys
\d revoked_credentials
\d sessions
```

If you migrated revocation stores from in-memory to Postgres during the v0.9.10.0 deploy (i.e. you were one of the deployments newly benefiting from the drift correction), v0.9.9.x ignores `IRevocationStore` injections silently — the type signature accepts the field but the verifier never reads from it. Revocation enforcement reverts to in-memory. **This is the pre-existing drift class that v0.9.10.0 corrected.** If you need durable revocation enforcement on the rolled-back version, you cannot get it on v0.9.9.x — that capability requires v0.9.10.0+.

## Re-applying v0.9.10.0 later

When the issue that triggered the rollback is resolved:

1. Reapply the v0.9.10.0 bootstrap changes (case #1, #2, or #4 from `docs/migration-byok.md` per your current state).
2. `npm install --save-exact @abaxxlabs/agents@0.9.10.0` (or the patch version that resolved the issue).
3. Restart.

There is no DB rollback to undo, so re-applying is a normal forward upgrade. Re-run the post-migration checklist from `docs/migration-byok.md` § "After the migration."

## Risks

- **In-flight sessions invalidated.** Users authenticated against v0.9.10.0 must re-authenticate after rollback. Bounded by your session TTL (default 4h).
- **Revocation durability lost** for consumers who newly migrated to a Postgres revocation store as part of the v0.9.10.0 deploy. v0.9.9.x cannot enforce revocation across instances or across restarts (the drift class). Plan accordingly.
- **Master-key state.** If the master key was rotated during the v0.9.10.0 window, the rolled-back application MUST be configured with the same master key value that wraps the column keys at rest. See §"Data-loss surface" above.
- **Audit chain unbroken.** Rollback does not invalidate or reorder the `agent_audit` hash chain. Entries written under v0.9.10.0 stay verifiable on v0.9.9.x because the hash logic is unchanged across this release (no new audit-record version, no schema change).

## Related

- Migration guide forward: `docs/migration-byok.md`
- CHANGELOG entry for v0.9.10.0: `CHANGELOG.md` § `[0.9.10.0]`
- Migration 007 rollback (revocations): `demo/hackathon/findings/session-plans/session-3-release/rollback-007.md`
- Migration 008 rollback (sessions): `demo/hackathon/findings/session-plans/session-5-release/rollback-008.md`
- v0.9.10.0 deploys do NOT add migrations — rollback procedures for 001–008 are unaffected by this release.
