# SQLite runtime feasibility evidence

## Decision

**PASS for the tested composition and fixed workload, with the lifecycle and audit limitations below.**

The canonical Playground image can run independent in-memory SQLite SDK stores with shared, role-restricted PostgreSQL pools. This is evidence for the combined feasibility review, not approval of production migration, concurrent audit ordering, hostile-SQL row isolation, routing, or user capacity.

Confidence is high for the operations and resource accounting actually exercised. Memory behavior beyond this short sequential workload and other CPU architectures remain unverified.

## Reproduction and provenance

From `demo/playground`, with Node.js 22+ on the host and Docker available:

```bash
npm run proof:sqlite-runtime
```

This builds the final image using the canonical Dockerfile, starts a fresh private PostgreSQL instance, runs 20 warmup and 200 measured cycles, observes a hard worker termination and fresh restart, and removes its disposable resources. The organizer does not expose an application port or require an external identity provider.

Recorded execution: **2026-11-04 17:06:23.660–17:07:03.324 UTC**. This replaces the historical SDK `0.51.1` execution of 2026-10-28; that earlier PASS is not evidence for the current composition.

| Property | Recorded value |
|---|---|
| Source baseline | `22e07d568b34545d1f2ffb3059f62b46599cf145` |
| Source state | Dirty: only `scripts/sqlite-runtime-proof/scenarios.mjs`, `scripts/sqlite-runtime-proof/runtime.mjs` and `README.md` under `demo/playground` differed at build time; executable-file hashes below identify the corrections |
| Image reference | `agents-playground-sqlite-proof:3430570-bf49c6eb` |
| Immutable local image ID/digest | `sha256:79f5926d874161ebc769d1acacaaaf04e9444ac20cffe58c3225f5fed18237e0` |
| Image build | Canonical `demo/playground/Dockerfile`, built during this execution |
| Runtime | Node `v22.23.2`, ABI `127`, Linux amd64, glibc runtime `2.36`, UID `1000` |
| Host organizer | Node `v24.13.1`, Docker Engine `29.7.1` |
| SDK | `0.55.0`, linked repository build under `/app/dist` |
| Native driver / SQLite | `better-sqlite3` `12.11.1` / SQLite `3.53.2` |
| Playground lock SHA-256 | `78120129e942f6d3ebd7004a93eaf42345266a76ad1712b57d81693148a66546` |
| PostgreSQL | `16.15 (Debian 16.15-1.pgdg12+2)`, `postgres:16-bookworm` |
| PostgreSQL image ID/digest | `sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938` |
| Worker limits | 512 MiB, 1 CPU, 128 PIDs, 1024 file descriptors |
| Pool limits | Query 2, raw 1; acquire timeout 3 s, statement timeout 5 s |

The image is a local build, not a published registry release. A new canonical build gets its own recorded image identity; `--image` explicitly reuses an existing image and validates its protocol, actual Node/user/SDK/driver provenance and image-lock checksum before accepting successful evidence. For exact local-image replay, select the immutable image ID above with `--image`. This report was updated after execution and is not represented by that image digest.

The only executable-source changes from the baseline are the corrected modified-record rejection assertion and the audit-limitations text. SDK source, manifests, lockfiles, Dockerfile, migrations and all other proof scripts match the baseline. The following SHA-256 values were checked against both the host files and the files inside the built image:

| Executable file under `demo/playground` | SHA-256 |
|---|---|
| `scripts/sqlite-runtime-proof/scenarios.mjs` | `90d43169ae7ed36f536947689759573bc9427cae13cca32541672354e6e7ebfb` |
| `scripts/sqlite-runtime-proof/runtime.mjs` | `b785092d71ee51d7eb1082c96e74bd8c18e6f595e43310a0b0410ec3e3bd662a` |

Full local output for this execution is in `test-results/sqlite-runtime-proof/3430570-bf49c6eb/report.json` and `report.md`. The JSON SHA-256 is `399b2b6fb7f2e17ccdea473e2940a2287078e906aa8aac383b1523c067f61bc1`. Those generated files are ignored. The checked-in summary below preserves the decision, observations and reproduction contract; rerunning the command regenerates all individual checks and samples.

### Regression reproduction

Before applying the correction, a fresh canonical build from the clean baseline above reproduced **FAIL** at `A-record-payload-mismatch-detected`, using SDK `0.55.0` and the same lock checksum. That execution is recorded in `test-results/sqlite-runtime-proof/3426095-fa7edbc3/report.json`; it did not reach teardown, cycles or worker restart. After correcting the assertion and descriptions, a newly built image completed the full default workload. Both `A-record-payload-mismatch-detected` and `B-record-payload-mismatch-detected` passed by requiring the SDK to reject a changed `rowCount` with its original signature retained. No SDK verification change was needed.

## Fixture and operations

- One fresh database receives the eleven existing canonical migrations, two deterministic orders and two encrypted columns. Migrations are reused, not changed.
- `proof_query` can SELECT only `orders`, `agent_keys` and `agent_columns`; `proof_raw` can SELECT only `orders_plaintext`. Both are non-superuser, non-owner/non-BYPASSRLS roles without database or role creation privileges.
- A and B have distinct SQLite databases and independent local DID owners/agents, but share process query/raw pools and the common encrypted dataset. The common fixture master key is copied into separately owned runtime buffers.
- Real SDK credentials and fresh signed presentations exercise decrypted reads, scope denial, the same SQL allowed by a broader credential, wrong-visitor credential denial and revocation.
- Audit evidence checks private storage, real signatures, equality with covered signed payload fields, complete chains, corrupt-signature rejection and SDK rejection of a modified signed field.
- Admission closes before teardown; accepted A work drains. Explicitly closed SQLite handles reject access. B executes another credentialed query and writes new audit after A is disposed.

## Acceptance observations

| Criterion | Result | Observed evidence |
|---|---|---|
| Native SQLite in actual image | PASS | Final build opens/initializes/closes SQLite through the public SDK as the non-root runtime user; actual native version recorded. |
| Isolated real SDK behavior | PASS | Independent agents/audit/revocations; real allow/deny, encrypted positive control, wrong-visitor denial, signatures and revocation checks. |
| Visitor teardown and shared pools | PASS | A admission rejected after close, accepted work drained, retained storage handles rejected, owned buffers overwritten, B and process pools remained operational. |
| Fixed lifecycle cycles and worker loss | PASS | 20 warmup + 200 measured cycles, complete resource accounting and samples, SIGKILL observed externally, fresh stores did not restore old identities/audit/revocations. |
| Reproducible result and evidence | PASS | Final JSON/Markdown report, immutable image identity, cleanup result, fail-closed evidence contracts and explicit limitations. |

### Resource observations

The initial two-runtime exercise plus 220 warmup/measured cycles created and closed **222 runtimes and 222 SQLite stores** in the measured worker. Final live runtime and tracked-operation counts were zero. Both PostgreSQL pools ended with total/idle/waiting counts zero.

| Observation | After warmup | After 200 measured cycles |
|---|---:|---:|
| RSS bytes | 121,597,952 | 110,964,736 |
| Linux file descriptors | 21 | 21 |
| Live runtimes | 0 | 0 |
| PostgreSQL query/raw waiting | 0 / 0 | 0 / 0 |

Nine post-warmup/measured samples produced an RSS delta of **−10,633,216 bytes**, with an observed least-squares slope of **−70,664.19 bytes/cycle**. Heap-used delta was **−313,144 bytes**; external and ArrayBuffer deltas were **−1,316,905** and **−1,325,801 bytes**, respectively. No forced garbage collection was used. The worker completed its checks/cycles and graceful pool closure in approximately **5.25 seconds**; this is not a user-throughput benchmark.

These numbers do not prove absence of all native/cryptographic retention or stable memory under longer/concurrent workloads. Allocator retention and process-global key caches affect interpretation.

### Hard termination and restart

- A separate worker held two real visitors, each with one agent and audit record; A also had one revocation.
- The host observed two PostgreSQL worker connections, sent SIGKILL and observed exit **137**, with `OOMKilled=false`.
- Polling observed zero worker PostgreSQL connections after **97 ms**; this is observation time, not an exact disconnect latency guarantee.
- The replacement worker started with zero agents/audit/revocations in both stores, could not find the old agent DIDs, created fresh agents and completed new protected queries against the same PostgreSQL fixture.
- Protected row count and ciphertext fingerprint were unchanged. PostgreSQL agent/audit/revocation/session/context tables stayed empty.
- The organizer removed five containers, their disposable database volume and the private network. A subsequent Docker listing found no remaining proof containers or networks.

## Required limitations and next design decisions

1. **SDK close is not complete capability destruction.** A retained direct `AgentScope.query()` succeeded after SDK close but before explicit SQLite close, and an externally retained agent signer remained usable. The proof wrapper enforces admission/draining and explicitly closes SQLite. Later integration must preserve that boundary; SDK close alone is insufficient.
2. **Zeroization is narrowly observed.** Caller-owned master/MAC/owner-key buffers were overwritten. Opaque signers, loaded column keys, immutable strings, temporary copies and imported-key caches are not demonstrated erased. Hard termination runs no graceful zeroization.
3. **Record verification and chain validation are distinct checks.** SDK `verifyRecord()` verifies the JWT signature and compares its signed payload with the supplied record's covered fields. It correctly rejected the changed `rowCount` with the original signature retained for both A and B. The proof independently detected the payload mismatch and its effect on the next chain link. For the query/rejection records exercised here, status/reason/reasonCode/version/previousHash are not signed; this does not describe all SDK audit record versions. Chain validation remains separate and does not prove absence of deleted records.
4. **Timestamp-tie concurrency is unproven.** SQLite selects the audit head by timestamp without a tie-breaker. This workload serializes each runtime and spaces audit timestamps. Concurrent query/audit behavior requires separate design validation before relying on this composition in serving.
5. **Session loss is not global credential invalidation.** A replacement runtime lacks old local identity and audit state. That does not establish cryptographic invalidity of every previously issued credential or durable revocation.
6. **Public-key verifiability is intentional.** B can verify A's authentic public DID signature; B cannot read A's private audit store. These are different properties.

Recommendation: use this evidence as the runtime/storage input to the combined feasibility gate. Carry the lifecycle, concurrent-audit and audit-verification limitations into that decision. Do not infer multi-worker routing, adversarial SQL isolation, production readiness or 100/1000-user capacity from this execution.

## Regression and local review

- `npm run typecheck`: passed.
- Root `npm test`: 130 files passed, 1,934 tests passed; 7 skipped and 3 todo in the existing suite. The real-image proof does not skip missing dependencies.
- `npm run build`: passed, ESM/CJS/shim.
- Playground `npm test`: 194 tests passed, including 13 native-packaging/reporting/cancellation contracts.
- The initial local Playground test attempt found an incomplete root `dist/`; rebuilding the root package before rerunning produced the 194-test PASS above.
- `npm run proof:sqlite-runtime`: reproduced FAIL before the fix and PASS after rebuilding, with all six phases (`fixture`, `run`, `kill`, `restart`, `postgres`, `cleanup`) passing and both worker evidence contracts satisfied.

## Sources

- https://www.sqlite.org/inmemorydb.html
- https://www.sqlite.org/lang_select.html#the_order_by_clause
- https://node-postgres.com/apis/pool
- https://nodejs.org/docs/latest-v22.x/api/process.html#processmemoryusage
- https://nodejs.org/docs/latest-v22.x/api/process.html#signal-events
- https://docs.docker.com/reference/dockerfile/#copy
- https://docs.docker.com/reference/cli/docker/image/inspect/
