# Worker routing, draining and fencing proof

Result: **PASS** — combined initial gate: **GO**

Initial gate PASS for the bounded two-worker composition. The real SDK runtime, fenced executor, owner-aware routing, drain/retire admission, transaction-bound ownership fencing and forged-hop rejection are proven on the egress-blocked internal network. Production rollout additionally requires mTLS/SPIFFE workload identity (stated, not satisfied by gateway-only header policy) and is out of scope for this proof.

Started: 2026-11-09T13:42:10.561Z
Finished: 2026-11-09T13:42:29.144Z

## Reproduction

```sh
npm run proof:worker-routing-fencing
```

## Prerequisite reports (merged)

- SQLite runtime proof: `reports/sqlite-runtime-proof.md` (PASS).
- SQL isolation proof: `reports/sandbox-isolation-proof.json` (PASS, 147 checks).
These two reports are inputs to the combined gate; this proof adds the routing, drain, lease, generation and fencing evidence.

## Environment

```json
{
  "sourceRevision": "0371ca4f3fceedc916bbb67b0334762e32d4c496",
  "workingTree": "clean",
  "hostNode": "v24.18.0",
  "docker": "29.8.2",
  "sdkVersion": "0.58.0",
  "build": "canonical Playground Dockerfile",
  "lockSha256": "461918bb6cc66170b76dcce1d194d019e71720afc712b83ae427996030aff54b",
  "image": {
    "reference": "agents-playground-wrfp:65919-67001a77",
    "id": "sha256:1e7f224330f7bb6ecaf7fd2140ea153fa8aebcbf3a20953cda4c290283e35c8a",
    "repoDigests": [
      "agents-playground-wrfp@sha256:1e7f224330f7bb6ecaf7fd2140ea153fa8aebcbf3a20953cda4c290283e35c8a"
    ],
    "architecture": "arm64",
    "os": "linux",
    "user": "node"
  },
  "modules": {
    "catalog.mjs": "e61da8b27b4e883f088e60f8a64823de22967f2a81cb0f1df92c244fc30c2b35",
    "catalog.sql": "36c97202eb104cd1fa181575ecce6aa27c6d87db0a189ae3810a4aec97a7a7a4",
    "evidence.mjs": "dadeb49973a2192faabb58cfd7dd8c9832e6abed538ebd8778d3f008ca5dff83",
    "executor.mjs": "787bc82cabcc5c4409089df72a13ac443bde368a364fb6c1525dddab33ac4512",
    "fixture.mjs": "7fde3c01bfbba0f9d6df9201d1b4a0458e516d4bdb443c7ce1df06156196f51f",
    "report.mjs": "0a52ee982f54aae23e011c74b5433ca1acee55080ea6e347f352cf517a64785c",
    "router.mjs": "10269d7beb0544c87ed4dbdbf8b9bfc76c08bd6278e965f2bc93477fb3549027",
    "scenarios.mjs": "a8e476d0eef7f081a9d9dff38ac77cb0ceef11be43cdc543f21a01e7d2ff4ccd",
    "worker.mjs": "995f906afd2855ee529244353dbce42e94f3ef4815669aacdf31c7f66e81e1dd"
  },
  "prerequisiteReports": {
    "reports/sqlite-runtime-proof.md": "8347ba7fefbdf2ef7f4733ef2ddb5c1fb541c311b0ac28a9154997e9009073e9",
    "reports/sandbox-isolation-proof.json": "b4e88cbcdca46384ca688e103133632bf5a8cfd0dbd10d462991da71c63fb66d"
  },
  "postgres": {
    "image": "postgres:16-bookworm",
    "id": "sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938",
    "repoDigests": [
      "postgres@sha256:e8a07d2c7579b038938cdba6c539e580e5001caf9ea203d397b5cc83e76bd938"
    ],
    "version": "16.15 (Debian 16.15-1.pgdg12+2)"
  }
}
```

## Combined gate

```json
{
  "go": true,
  "runtimeLifecycle887": "PASS",
  "sqlIsolation888": "PASS",
  "routingDrainingFencing": true,
  "staleOwnerSafety": true,
  "workerShutdown": true
}
```

## Acceptance

- Criterion 1: PASS. Every real operation from both entry points on both sandboxes resolves to the same live owner + generation (no new identity minted on forward); duplicate and cross-sandbox reservations are refused; the runtime DID is persisted and stable; static/healthz/readyz are unrouted; the JSON body survives the hop chain.
- Criterion 2: PASS. A drained worker records a deadline and marks its existing sessions draining; a concurrent admission racing the drain is refused by the in-transaction catalog gate with no session row written (F5); new-session admission stays closed while readyz stays alive; forced retirement keeps admission closed with no SDK state migrated or recreated; the janitor reaps the retired owner session lost.
- Criterion 3: PASS. Ownership is fenced at the mutation transaction boundary: a stale generation rolls back (409, fenced pre, no commit); an expired lease is terminal until renewed; the in-flight advisory lock makes the janitor defer and a generation bump AND an ownership transfer fail (55P03, F3); the pre-commit fence rejects a passed drain deadline and a retired owner (F2) with no partial write; a resumed stale owner cannot commit and a lost session is not resurrected; a transfer to a non-holder is incompatible-runtime (F7) until ownership returns to the holder. Transaction-level evidence recorded.
- Criterion 4: PASS. A dead owner session is reaped LOST and every entry point returns a defined session-lost (no random reroute); a catalog outage makes a mutation fail closed with dependency-unavailable and no ambiguous commit, and recovery resumes the same owner/session/generation.
- Criterion 5: PASS. Forged internal hops are rejected per vector (bad/cross signature, hop-limit, deadline, stale generation, wrong destination, missing headers) while a valid hop executes; the catalog control surface is an explicit EXECUTE allowlist -- PUBLIC and the data-plane roles are denied every privileged function (verified by has_function_privilege AND a real 42501 execution probe) and keep only the fence/read surface (F1); the public surface enforces the Origin allowlist and expected Host before any route handling (W2). The production mTLS/SPIFFE workload-identity requirement is STATED, not claimed, and gateway-only header policy is not sufficient.
- Criterion 6: PASS. Combined initial go/no-go: cites the merged 887 SQLite runtime (PASS, verified by the driver from the image) and 888 SQL isolation (PASS) reports; the routing/drain/fencing/stale-owner matrix from this proof is all-PASS, so the bounded two-worker composition passes the initial gate. This is not production migration, capacity, HA, or durable-session approval.

## Worker shutdown

- worker-a: status PASS, cleanup PASS
- worker-b: status PASS, cleanup PASS

## Driver checks

| Check | Result |
|---|---|
| matrix-clean-start | PASS |
| matrix-create-owners | PASS |
| matrix-create-persists-did | PASS |
| matrix-status-A-owner | PASS |
| matrix-status-A-nonowner | PASS |
| matrix-status-B-owner | PASS |
| matrix-status-B-nonowner | PASS |
| matrix-query-A-owner | PASS |
| matrix-query-A-nonowner | PASS |
| matrix-query-B-owner | PASS |
| matrix-query-B-nonowner | PASS |
| matrix-rawsql-A-owner | PASS |
| matrix-rawsql-A-nonowner | PASS |
| matrix-rawsql-B-owner | PASS |
| matrix-rawsql-B-nonowner | PASS |
| matrix-agents-A-owner | PASS |
| matrix-agents-A-nonowner | PASS |
| matrix-agents-B-owner | PASS |
| matrix-agents-B-nonowner | PASS |
| matrix-present-A-owner | PASS |
| matrix-present-A-nonowner | PASS |
| matrix-present-B-owner | PASS |
| matrix-present-B-nonowner | PASS |
| matrix-delegate-A-owner | PASS |
| matrix-delegate-A-nonowner | PASS |
| matrix-delegate-B-owner | PASS |
| matrix-delegate-B-nonowner | PASS |
| matrix-audit-A-owner | PASS |
| matrix-audit-A-nonowner | PASS |
| matrix-audit-B-owner | PASS |
| matrix-audit-B-nonowner | PASS |
| matrix-renew-A-owner | PASS |
| matrix-renew-A-nonowner | PASS |
| matrix-renew-B-owner | PASS |
| matrix-renew-B-nonowner | PASS |
| matrix-mutate-A-owner | PASS |
| matrix-mutate-A-nonowner | PASS |
| matrix-mutate-B-owner | PASS |
| matrix-mutate-B-nonowner | PASS |
| matrix-reset-A-owner | PASS |
| matrix-reset-A-nonowner | PASS |
| matrix-reset-B-owner | PASS |
| matrix-reset-B-nonowner | PASS |
| matrix-rawbytes-A-owner | PASS |
| matrix-rawbytes-A-nonowner | PASS |
| matrix-rawbytes-B-owner | PASS |
| matrix-rawbytes-B-nonowner | PASS |
| matrix-ping-A-owner | PASS |
| matrix-ping-A-nonowner | PASS |
| matrix-ping-B-owner | PASS |
| matrix-ping-B-nonowner | PASS |
| matrix-final-quantity-seed-A | PASS |
| matrix-final-quantity-seed-B | PASS |
| matrix-duplicate-refused | PASS |
| matrix-ping-body-transport | PASS |
| matrix-reset-restores-seed | PASS |
| matrix-did-stable-A | PASS |
| matrix-did-stable-B | PASS |
| matrix-no-new-identity-on-forward | PASS |
| matrix-one-live-session-per-sandbox | PASS |
| matrix-unknown-cookie-410 | PASS |
| matrix-non-owner-forwarded | PASS |
| matrix-static-unrouted-root | PASS |
| matrix-static-unrouted-healthz | PASS |
| matrix-static-unrouted-readyz | PASS |
| matrix-cleared | PASS |
| drain-recorded-deadline | PASS |
| drain-session-marked-draining | PASS |
| drain-admission-race-rejected | PASS |
| drain-admission-race-no-row | PASS |
| drain-new-session-refused | PASS |
| drain-readyz-alive-admission-closed | PASS |
| drain-existing-status-alive | PASS |
| drain-existing-query-alive | PASS |
| drain-worker-a-restored-active | PASS |
| retire-control-applied | PASS |
| retired-no-admission | PASS |
| drain-no-state-migration | PASS |
| drain-janitor-reaps-retired-worker-session | PASS |
| drain-reaped-session-lost-generation-bumped | PASS |
| drain-state-discarded-on-loss | PASS |
| drain-worker-reset-active | PASS |
| dead-owner-janitor-reaps-lost | PASS |
| dead-owner-session-lost | PASS |
| dead-owner-worker-drops-belief | PASS |
| dead-owner-no-reroute-lost | PASS |
| dead-owner-state-discarded | PASS |
| catalog-down-mutation-fails-closed | PASS |
| catalog-down-no-ambiguous-commit | PASS |
| catalog-recovered-same-session | PASS |
| dead-owner-worker-restored-active | PASS |
| fence-reset-commits | PASS |
| fence-bump-applied | PASS |
| fence-stale-generation-rejected | PASS |
| fence-stale-mutation-not-committed | PASS |
| fence-transaction-evidence | PASS |
| fence-revalidate-adopts-generation | PASS |
| fence-renewal-after-revalidate | PASS |
| fence-current-generation-commits | PASS |
| fence-current-mutation-committed | PASS |
| fence-lease-expired-rejected | PASS |
| fence-lease-expired-not-committed | PASS |
| fence-lease-renew-restores | PASS |
| fence-inflight-holds-advisory-lock | PASS |
| fence-janitor-defers-inflight | PASS |
| fence-bump-blocked-while-inflight | PASS |
| fence-transfer-blocked-while-inflight | PASS |
| fence-drain-deadline-rejected | PASS |
| fence-lock-released-after-inflight | PASS |
| fence-inflight-no-partial-write | PASS |
| fence-janitor-reaps-drained | PASS |
| fence-drained-session-deleted-generation-bumped | PASS |
| fence-drain-runtime-discarded | PASS |
| fence-owner-retired-rejected | PASS |
| fence-owner-retired-not-committed | PASS |
| fence-janitor-reaps-owner-dead | PASS |
| fence-reaped-owner-dead-lost | PASS |
| fence-worker-restored-active | PASS |
| fence-stale-resume-rejected | PASS |
| fence-stale-resume-not-committed | PASS |
| fence-stale-resume-revalidate-report | PASS |
| fence-transfer-stable-runtime-identity | PASS |
| fence-transfer-bumps-generation | PASS |
| fence-transfer-old-entry-incompatible | PASS |
| fence-transfer-nonholder-incompatible | PASS |
| fence-transfer-no-new-identity | PASS |
| fence-transfer-back-holder-report | PASS |
| forged-hop-bad-signature-rejected | PASS |
| forged-hop-hop-limit-rejected | PASS |
| forged-hop-deadline-rejected | PASS |
| forged-hop-stale-generation-rejected | PASS |
| forged-hop-cross-secret-rejected | PASS |
| forged-hop-wrong-destination-rejected | PASS |
| forged-hop-missing-headers-rejected | PASS |
| forged-hop-valid-hop-accepts | PASS |
| priv-public-no-privileged-execute | PASS |
| priv-data-roles-no-privileged-execute | PASS |
| priv-control-allowlist-complete | PASS |
| priv-data-roles-keep-safe-reads | PASS |
| priv-unauthorized-call-denied-42501 | PASS |
| public-origin-foreign-rejected | PASS |
| public-origin-allowed-accepts | PASS |
| public-host-foreign-rejected | PASS |
| public-host-allowed-accepts | PASS |
| prereq-runtime-lifecycle-887 | PASS |
| prereq-sql-isolation-888 | PASS |
| combined-gate-catalog-snapshot | PASS |

## Workload identity

```json
{
  "internalHop": [
    "per-worker-hmac",
    "hop-limit-1",
    "deadline-window",
    "destination-self-check",
    "catalog-re-resolve"
  ],
  "networkIsolation": "internal-docker-network-egress-blocked",
  "productionRequirement": "mTLS-or-SPIFFE-workload-identity-required; gateway-only-header-policy-is-NOT-sufficient",
  "claimed": false
}
```

Machine-readable checks, fault sequences and failure stages are in report.json.

## Sources

- https://node-postgres.com/apis/pool
- https://www.postgresql.org/docs/16/explicit-locks.html
- https://nodejs.org/api/process.html
