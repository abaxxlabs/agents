# Architecture Decisions

Cross-cutting design decisions that apply to multiple files in `@abaxxlabs/agents`. Inline code comments link here when the *why* matters but does not need to be repeated in the source.

Format: each entry states the decision, the reason it was made, and what it means for a consumer of the library.

---

## D-001 — Two-parameter `AgentScope.create(config, injections)` factory

**Decision:** the public factory takes two arguments: `config` (static description: database connection, OIDC, encryption columns, audit) and `injections` (runtime resources: master key, storage backend, optional pool, sdk, server identity).

**Why:** the master key and pluggable infrastructure must be sourced explicitly by the consumer. The library does not read `process.env` for any cryptographic material. This unblocks BYOK — consumers can source keys from KMS, HSM, sealed secrets, or any custodial pattern of their choice.

**For consumers:** `injections.masterKey` is required. The convenience env-var helper lives at `@abaxxlabs/agents/bootstrap` (`resolveMasterKeyFromEnv`). Library core never touches `process.env.AGENTS_MASTER_KEY`.

---

## D-002 — Lifecycle ownership flags (`ownsPool`, `ownsStorage`)

**Decision:** `AgentScope.close()` only ends the `pg.Pool` and the `StorageBackend` when AgentScope built them itself. Caller-supplied resources stay open after `close()`.

**Why:** multi-tenant orchestrators run many AgentScope instances against a single shared pool; closing the pool would yank it from sibling instances. Same applies to a shared storage backend.

**For consumers:** if you pass `injections.pool` or `injections.storage`, you own their lifecycle. AgentScope leaves them alone.

---

## D-003 — Default storage backend is constructed but not initialized

**Decision:** when `injections.storage` is omitted, AgentScope builds a `PostgresStorageBackend` from `config.database.connectionString` but does NOT call `.initialize()` on it.

**Why:** `initialize()` runs schema migrations, revocation-cache warm-up, and coherency polling. Migrations are a deployment concern (rename/reshape tables, partial-failure handling, controlled rollouts) — running them from a constructor turns any code path that calls `AgentScope.create` into an unintended migration runner.

**For consumers:** single-instance demos and dev runs work as-is (revocation cache starts cold; `isRevoked()` falls through to a Postgres query on miss). Multi-instance production must inject a pre-initialized backend via `injections.storage`. There is no silent in-memory fallback — Postgres in, Postgres out.

---

## D-004 — Per-instance server identity (`verifierDid`)

**Decision:** every `AgentScope` has its own DID, used as the audience for Verifiable Presentations. Generated at construction unless `injections.serverIdentity` is supplied.

**Why:** VPs are bound to a specific verifier. Without per-instance identity, an agent's VP to Server A could be replayed against Server B.

**For consumers:** in production, pass a persistent server identity (see `initializeServerIdentity`). Without it, every restart invalidates outstanding VPs that were bound to the prior `verifierDid`.

---

## D-005 — Best-effort master-key zeroing on `close()`

**Decision:** `AgentScope.close()` writes zeros into the `masterKey` buffer.

**Why:** shrinks the lifetime of the secret to the AgentScope lifetime, and zeroises any heap snapshot or core dump captured *after* close.

**Caveat:** V8 is a moving collector — it may have already copied the buffer's bytes during GC compaction. This is a best-effort defence, not a hard guarantee. Consumers requiring hard memory guarantees should source the master key from an HSM/KMS that never hands raw bytes to the JS heap.

---

## D-006 — Redaction at every serialization sink (`toJSON`, `inspect.custom`)

**Decision:** `AgentScope.toJSON()` and `AgentScope[inspect.custom]()` both return a redacted snapshot in which `masterKey` is `'[REDACTED 32 bytes]'` and `sdk` is `'[SDK]'` or `'[none]'`. The two methods delegate to a single source of truth.

**Why:** the `MasterKey` brand type blocks at compile time, but `console.log`, `JSON.stringify`, and `util.inspect` all accept `any`/`unknown` — widening the brand cannot block. Runtime redaction is the second layer.

**For consumers:** `console.log(scope)` and `JSON.stringify(scope)` are safe. No hex of the master key appears in either.

---

## D-007 — Mock authentication is gated by `NODE_ENV`, not by config alone

**Decision:** `AgentScope.authenticate({ mockHumanDid })` throws unless `NODE_ENV` is `development` or `test`, even if `config.devMode` is true.

**Why:** defense in depth. If a misconfigured production deploy ships with `devMode: true` in config, the runtime gate still refuses to issue mock identities.

**For consumers:** real OIDC must be used in production. Mock auth is not an opt-in feature, it is a development affordance.

---

## D-008 — Delegation requires cryptographic verification of the source credential

**Decision:** `delegateCredential()` verifies the source credential's signature, expiry, and issuer-owner binding before issuing a delegated credential.

**Why:** without this, an attacker who knows a live `sourceAgentDid` could supply a forged JWT and receive a server-signed delegated credential.

**For consumers:** delegation has the same trust requirements as direct issuance. The supervisor must hold a valid credential whose issuer is the registered owner of the supervisor agent.

---

## D-009 — `ownerDid` is required on `createAgent()`

**Decision:** `createAgent()` throws if `ownerDid` is not supplied. There is no `'demo-owner'` default.

**Why:** an unbound default means any session can create agents with no ownership chain. Production audit and revocation flows depend on the agent being attributable to a human DID.

**For consumers:** pass `authSession.humanDid` from an authenticated session.

---

## D-010 — `AGENTS_*` environment variables are not read inside the library

**Decision:** the library reads only two `process.env` values directly: `NODE_ENV` (defense-in-depth gate for mock auth) and `CI` (test-harness signal in `keystore.ts`). Every other configuration value is sourced from `AgentScopeConfig` or `injections`.

**Why:** a library that reaches into the host environment couples consumers to a single deployment pattern. Removing these reads unblocks consumers who source configuration from sealed secrets, KMS, or other custodial systems.

**For consumers:** the convenience env-var helpers (`resolveMasterKeyFromEnv`, etc.) live in `@abaxxlabs/agents/bootstrap`, an explicit subpath. Consumers who want env-var bootstrapping import from there; consumers who do not will find the library does not read `AGENTS_*` on their behalf.

---

## D-011 - REST/MCP shared API boundary

**Decision:** REST routes and MCP tools should share transport-neutral application services. REST is not the canonical implementation surface for MCP, and the existing `src/mcp/rest-bridge.ts` stub should not be wired as the default path before publish.

**Why:** MCP ships with the library and must stay usable without a REST server, while REST still needs hardening. Shared services let both transports reuse query, audit, identity, validation, rate-limit, and error behavior without coupling MCP to HTTP route names or a localhost hop.

**For consumers:** MCP tool names and arguments remain operation-focused. Future internal refactors may move the tools from direct `AgentScope` calls to shared services, but callers should not depend on REST URLs, HTTP status codes, or `src/mcp/rest-bridge.ts`. See `docs/adr-rest-mcp-shared-api.md` for the implementation plan.

**Package output policy:** `src/mcp/rest-bridge.ts` is source-only reference material. It is intentionally excluded from ESM/CJS build outputs, omitted from the npm package file list, and absent from `package.json` exports. The supported MCP import path remains `@abaxxlabs/agents/mcp`.

---

## D-012 - Public API snapshot for release subpaths

**Decision:** the supported 0.11.3 public surface is limited to six package exports: root, `/sql`, `/mcp`, `/storage`, `/sqlite`, and `/bootstrap`. CI snapshots the exported names and whether each name is type-only, value-only, or both.

**Why:** barrel exports are easy to change accidentally during internal refactors. A snapshot turns every exported-name addition, removal, or type/value kind change into an intentional release-contract review.

**For consumers:** new public symbols are not shipped by accident. If a future release adds a symbol, the snapshot must be updated in the same change that documents and tests the new contract.

---

## D-013 - MCP HTTP per-connection session map; single-human-DID per process

**Decision:** `src/mcp/http-handler.ts` owns a `Map<sessionId, SSEServerTransport>` keyed by the SDK-generated UUID. Concurrent SSE clients are routed independently; `POST /messages?sessionId=<uuid>` returns `400 invalid_session` on missing or unknown IDs. The MCP process remains single-human-DID per boot.

**Why:** the prior closure-scoped single transport reference (`let sseTransport`) overwrote on every reconnect and routed every `/messages` POST to the last connector, producing cross-client message leakage and a session-hijack path on bearer rotation (CWE-384, CWE-863). Audit closeout for HIGH-3 in ABXAGNTS-370.

**For consumers:** multiple MCP clients per human are supported within one process (CLI plus IDE under the same identity). Different humans require different processes. A strict single-connection mode (409 on second `/sse`) is deferred behind a future config flag. See `docs/adr-mcp-http-session-model.md` for the full rationale.
