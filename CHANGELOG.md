# [0.22.0](https://github.com/abaxxtech/agents/compare/v0.21.3...v0.22.0) (2026-08-24)


### Features

* **docs-site:** add installation, overview, quick start, interfaces, and security documentation ([b32fa52](https://github.com/abaxxtech/agents/commit/b32fa528a1f3cce45f1cdedd45023596d3bbe08f))

## [0.21.3](https://github.com/abaxxtech/agents/compare/v0.21.2...v0.21.3) (2026-08-24)


### Bug Fixes

*: Remove unused scoped-query instance state ([b635965](https://github.com/abaxxtech/agents/commit/b63596524bae4d2906b72f4dbad7ffc0e6d2d723))

## [0.21.2](https://github.com/abaxxtech/agents/compare/v0.21.1...v0.21.2) (2026-08-21)


### Bug Fixes

*: move AgentScope into its own module ([218eec9](https://github.com/abaxxtech/agents/commit/218eec99a0a293ab7bedced66593b14b844fcd32))

## [0.21.1](https://github.com/abaxxtech/agents/compare/v0.21.0...v0.21.1) (2026-08-21)


### Bug Fixes

*: align scoped-query doc with projection enforcement ([f408317](https://github.com/abaxxtech/agents/commit/f408317bcc81fa19d8e559f24adffb00e06600a3))

# [0.21.0](https://github.com/abaxxtech/agents/compare/v0.20.4...v0.21.0) (2026-08-21)


### Bug Fixes

* update registerIdentityTools to use registerTool for better clarity ([dd70a57](https://github.com/abaxxtech/agents/commit/dd70a57fd8de743942bb248674c59f8c5742e3a5))


### Features

* **docs-site:**: restructure documentation site and add landing page ([711ecd1](https://github.com/abaxxtech/agents/commit/711ecd1b72936fcfde39595b8e645d29fcd5b3fc))

## [0.20.4](https://github.com/abaxxtech/agents/compare/v0.20.3...v0.20.4) (2026-08-21)


### Bug Fixes

* persist v3 audit columns in SQLite store ([b245dbc](https://github.com/abaxxtech/agents/commit/b245dbc3873bd7338eed27748a3509d668e0d266))
* pin Bun version in jsdoc workflow ([cdf1a37](https://github.com/abaxxtech/agents/commit/cdf1a372e4fe958d93530cf2ea448fd62c8ce811))
* support MCP registerTool in rate-limit test harness ([6bc146f](https://github.com/abaxxtech/agents/commit/6bc146fe5cf6a50b87555d73bc7f07c826b14626))

## [0.20.3](https://github.com/abaxxtech/agents/compare/v0.20.2...v0.20.3) (2026-08-20)


### Bug Fixes

*: Centralize first-party license notices ([bb9c76d](https://github.com/abaxxtech/agents/commit/bb9c76d47d00a730ead00d95d773a51db4637295))
*: update tests and add agents rule ([533639a](https://github.com/abaxxtech/agents/commit/533639ad033598fe92261206fbeed00e9118c1e9))

## [0.20.2](https://github.com/abaxxtech/agents/compare/v0.20.1...v0.20.2) (2026-08-20)


### Bug Fixes

*: give session and revocation stores separate SQLite paths ([ef1a779](https://github.com/abaxxtech/agents/commit/ef1a7796f8183dff587b85f22b49be63c3c7d419))

## [0.20.1](https://github.com/abaxxtech/agents/compare/v0.20.0...v0.20.1) (2026-08-19)


### Bug Fixes

* Replace deprecated MCP tool and resource registration APIs ([b27ce47](https://github.com/abaxxtech/agents/commit/b27ce473ae25b67e5c129b44eca03b2bda457bc9))

# [0.20.0](https://github.com/abaxxtech/agents/compare/v0.19.1...v0.20.0) (2026-08-19)


### Features

*: add documentation sync and boundary check scripts with manifest validation ([9231e33](https://github.com/abaxxtech/agents/commit/9231e33d557ce1324ce05193713da311450fb7e2))

## [0.19.1](https://github.com/abaxxtech/agents/compare/v0.19.0...v0.19.1) (2026-08-19)


### Bug Fixes

*: key rate limits by human across REST and MCP ([64113c8](https://github.com/abaxxtech/agents/commit/64113c8b49cb8c2d0c7efaf411fbc66e220f8257))

# [0.19.0](https://github.com/abaxxtech/agents/compare/v0.18.0...v0.19.0) (2026-08-13)


### Features

* Present both blocked attacks in a simpler Demo V2 Beat 6 ([19fcf6c](https://github.com/abaxxtech/agents/commit/19fcf6c781dc30c7fe7314d8a162a428123ede7a))

# [0.18.0](https://github.com/abaxxtech/agents/compare/v0.17.0...v0.18.0) (2026-08-13)


### Bug Fixes

* refine V2 audit chain navigation ([c74b944](https://github.com/abaxxtech/agents/commit/c74b944dc85dc822ee7a1135ce80f08b59332dd4))


### Features

* add V2 audit registry and tamper test ([14d1c84](https://github.com/abaxxtech/agents/commit/14d1c8475015b1d95e110fb4c17f9ebbc9684c41))

# [0.17.0](https://github.com/abaxxtech/agents/compare/v0.16.0...v0.17.0) (2026-08-13)


### Features

* refactor V2 Beat 4 pipeline ([d0fe77d](https://github.com/abaxxtech/agents/commit/d0fe77d58942cdd014858b501d8612c7cbe35b0e))

# [0.16.0](https://github.com/abaxxtech/agents/compare/v0.15.5...v0.16.0) (2026-08-13)


### Bug Fixes

* guard V2 credential map ([5530ff5](https://github.com/abaxxtech/agents/commit/5530ff52f1f42b8409684a70f17dce706887dcd1))


### Features

* build V2 identity ceremony ([8aa848c](https://github.com/abaxxtech/agents/commit/8aa848c6f4ce7db8180bcde46b7d4fcecf665cb6))
* implement V2 Beat 3 scope comparison ([8d6a0b9](https://github.com/abaxxtech/agents/commit/8d6a0b92c68af26da5de02cd4783629763410490))
* refine V2 identity ceremony ([7a80d02](https://github.com/abaxxtech/agents/commit/7a80d020e8f6c82a989a9a7c59a459635249b37c))

## [0.15.5](https://github.com/abaxxtech/agents/compare/v0.15.4...v0.15.5) (2026-08-13)


### Bug Fixes

* harden NumericDate validation ([4d35df0](https://github.com/abaxxtech/agents/commit/4d35df046ed5d0225a56df70592ab1cd9af174f5))

## [0.15.4](https://github.com/abaxxtech/agents/compare/v0.15.3...v0.15.4) (2026-08-13)


### Bug Fixes

*: route MCP resources through services ([5cd47b5](https://github.com/abaxxtech/agents/commit/5cd47b5b883f2c0b2b8f587994235bba79c3fd31))

## [0.15.3](https://github.com/abaxxtech/agents/compare/v0.15.2...v0.15.3) (2026-08-11)


### Bug Fixes

* ABXAGNTS: refactor repository agent guidance ([f561289](https://github.com/abaxxtech/agents/commit/f561289f5df3e2b97e0c5f031455e1aea4581b75))

## [0.15.2](https://github.com/abaxxtech/agents/compare/v0.15.1...v0.15.2) (2026-08-10)


### Bug Fixes

*: split ScopeEngine query into focused modules ([a3c3e6a](https://github.com/abaxxtech/agents/commit/a3c3e6aa263be3715078578d01d364c7af3fe593))
*: update documentation ([085f698](https://github.com/abaxxtech/agents/commit/085f69809a2217b9d0114cc08a0533472f1facf9))

## [0.15.1](https://github.com/abaxxtech/agents/compare/v0.15.0...v0.15.1) (2026-08-10)


### Bug Fixes

* split mcp tool into domain-specific modules ([925feb2](https://github.com/abaxxtech/agents/commit/925feb2c1c61d30da6da3a70d6fc40991cab9b3d))
*: fix tests ([634fe66](https://github.com/abaxxtech/agents/commit/634fe66ef93d91d28d193ea121ec3b525f923f0b))

# [0.15.0](https://github.com/abaxxtech/agents/compare/v0.14.14...v0.15.0) (2026-08-10)


### Features

*: Build the Demo V2 problem screen ([bd76423](https://github.com/abaxxtech/agents/commit/bd764232a9a15e6ea0859eba8f5ccbd9d49dffe1))

## [0.14.14](https://github.com/abaxxtech/agents/compare/v0.14.13...v0.14.14) (2026-08-07)


### Bug Fixes

* **audit:** run public artifact audit when invoked as a CLI ([e911c7a](https://github.com/abaxxtech/agents/commit/e911c7abd4e1efa21337d3e17effda3562c03ff2))

## [0.14.13](https://github.com/abaxxtech/agents/compare/v0.14.12...v0.14.13) (2026-08-05)


### Bug Fixes

* reject scoped queries without read auth ([455af42](https://github.com/abaxxtech/agents/commit/455af423c97727fa41acec4ff6fd95dd920a5d79))
*: remove self explanatory comments ([f344a08](https://github.com/abaxxtech/agents/commit/f344a0840074c13356821555d4b212b2bde3b783))

## [0.14.12](https://github.com/abaxxtech/agents/compare/v0.14.11...v0.14.12) (2026-08-05)


### Bug Fixes

* comments ([46249e1](https://github.com/abaxxtech/agents/commit/46249e1bf98bc4041657ddd4d3f74ef4c6afe5a9))
*: align the scoped-query credential contract ([ca1ff82](https://github.com/abaxxtech/agents/commit/ca1ff827025c97885689dc926efe1bf54542d6b0))

## [0.14.11](https://github.com/abaxxtech/agents/compare/v0.14.10...v0.14.11) (2026-08-05)


### Bug Fixes

*: add missing rate limiting ([29cfedd](https://github.com/abaxxtech/agents/commit/29cfeddbd43e70f68641a378982a4be7ea374cc3))
*: Session rehydrate collapses scope ceiling to deny-all ([10c6db9](https://github.com/abaxxtech/agents/commit/10c6db9923de501cc3712c45b1a535cd9abc484f))
* pr comments ([9b8f313](https://github.com/abaxxtech/agents/commit/9b8f313b61c93ade50cff29f807e47293b79d23f))

## [0.14.10](https://github.com/abaxxtech/agents/compare/v0.14.9...v0.14.10) (2026-08-04)


### Bug Fixes

* **showcase:** remove retired legacy scenarios ([1d8fe4e](https://github.com/abaxxtech/agents/commit/1d8fe4e8a36bab296e31acb653ad357489773341))

## [0.14.9](https://github.com/abaxxtech/agents/compare/v0.14.8...v0.14.9) (2026-07-29)


### Bug Fixes

* harden mirror audit and release provenance checks ([#259](https://github.com/abaxxtech/agents/issues/259)) ([2df6060](https://github.com/abaxxtech/agents/commit/2df60605e1aa22adb096d047b436d1f0bfe3caa3))

## [0.14.8](https://github.com/abaxxtech/agents/compare/v0.14.7...v0.14.8) (2026-07-24)


### Bug Fixes

* include tests in public mirror sync ([#255](https://github.com/abaxxtech/agents/issues/255)) ([b509a5c](https://github.com/abaxxtech/agents/commit/b509a5cc03cd6d627ff0a06d45a6075db8b2c7f0))

## [0.14.7](https://github.com/abaxxtech/agents/compare/v0.14.6...v0.14.7) (2026-07-24)


### Bug Fixes

* align public mirror sync with release guardrails ([eeeb57e](https://github.com/abaxxtech/agents/commit/eeeb57e683437f6108972d9005a7c0773858d383))

## [0.14.6](https://github.com/abaxxtech/agents/compare/v0.14.5...v0.14.6) (2026-07-23)


### Bug Fixes

*: Enhance error handling and logging in SQLite and PostgreSQL storage backends ([03cccd9](https://github.com/abaxxtech/agents/commit/03cccd9d3cd77e5ebd1c649d277b21f965cd581a))
*: Refactor storage folder for improved clarity and performance ([f9d569f](https://github.com/abaxxtech/agents/commit/f9d569fc1cf3d52a2020e226ae1a5efdb7c89ad2))

## [0.14.5](https://github.com/abaxxtech/agents/compare/v0.14.4...v0.14.5) (2026-07-08)


### Bug Fixes

* sync showcase lockfile and preserve linked package resolution ([6ff5d9d](https://github.com/abaxxtech/agents/commit/6ff5d9d00cd5c40703584ad828bc23863fdf4110))
* sync showcase lockfile and preserve linked package resolution ([0159725](https://github.com/abaxxtech/agents/commit/0159725d4fe720bf1a8324cbe1cede4ec98379e6))
* sync showcase lockfile and preserve linked package resolution ([6625f2b](https://github.com/abaxxtech/agents/commit/6625f2bd55501dcba0145b461dd341a36215c2cb))

## [0.14.4](https://github.com/abaxxtech/agents/compare/v0.14.3...v0.14.4) (2026-07-06)


### Bug Fixes

* include lint/build configs in public mirror ([#246](https://github.com/abaxxtech/agents/issues/246)) ([42d43d8](https://github.com/abaxxtech/agents/commit/42d43d85e5f0112f92310c85001c093afc3d4f01))

## [0.14.3](https://github.com/abaxxtech/agents/compare/v0.14.2...v0.14.3) (2026-07-06)


### Bug Fixes

* fix public ci sync ([3a73c3f](https://github.com/abaxxtech/agents/commit/3a73c3f832b2b835bf32d0d9d1a6458afe13aee5))

## [0.14.2](https://github.com/abaxxtech/agents/compare/v0.14.1...v0.14.2) (2026-07-06)


### Bug Fixes

* remove stale failOpen smoke config ([7e445fe](https://github.com/abaxxtech/agents/commit/7e445fec0d9180705bcfb0c791ea0a684db3fc3a))

## [0.14.1](https://github.com/abaxxtech/agents/compare/v0.14.0...v0.14.1) (2026-07-06)


### Bug Fixes

* repair user-stories imports after src/identity rebuild ([b2545f4](https://github.com/abaxxtech/agents/commit/b2545f4645f36b1fee940233690cd5ad99c7d057))

# [0.14.0](https://github.com/abaxxtech/agents/compare/v0.13.3...v0.14.0) (2026-06-29)


### Features

* add lazy MCP Tool Schema Loading assessment and measurement script ([c8a4276](https://github.com/abaxxtech/agents/commit/c8a42764633ddfeef355b40439ab3f09672a6e2b))

## [0.13.3](https://github.com/abaxxtech/agents/compare/v0.13.2...v0.13.3) (2026-06-26)


### Bug Fixes

* install server deps separately for typecheck in precommit and release gate ([#238](https://github.com/abaxxtech/agents/issues/238)) ([0d41b9f](https://github.com/abaxxtech/agents/commit/0d41b9f001ba70f395b860efb76f54f223ded012))

## [0.13.2](https://github.com/abaxxtech/agents/compare/v0.13.1...v0.13.2) (2026-06-12)


### Bug Fixes

* allow newline between audit token and severity in sync regex ([dd2988c](https://github.com/abaxxtech/agents/commit/dd2988cfb8e52459058879f3e673d00d9a9d68c8))
* updating regex to not remove newlines ([bc5df3e](https://github.com/abaxxtech/agents/commit/bc5df3e86938a9c55eda2de46d40c73d6caaef0d))

## [0.13.1](https://github.com/abaxxtech/agents/compare/v0.13.0...v0.13.1) (2026-06-12)


### Bug Fixes

* exclude package version from public API snapshots ([8188c0f](https://github.com/abaxxtech/agents/commit/8188c0ff523d2d3721e94129f79b06f9d74b9751))

# [0.13.0](https://github.com/abaxxtech/agents/compare/v0.12.7...v0.13.0) (2026-06-12)


### Features

* add live OpenAI agent mode to showcase Beat 3 (overscope + prompt injection) ([#223](https://github.com/abaxxtech/agents/issues/223)) ([6ce479a](https://github.com/abaxxtech/agents/commit/6ce479a3bf98152c046c79be40c5007d56d9d65d))

## [0.12.7](https://github.com/abaxxtech/agents/compare/v0.12.6...v0.12.7) (2026-06-12)


### Bug Fixes

* correct credential-issuance link extension (.js → .ts) ([f8c672b](https://github.com/abaxxtech/agents/commit/f8c672b3bbf7125eea654bffa1a192516066bb06))

## [0.12.6](https://github.com/abaxxtech/agents/compare/v0.12.5...v0.12.6) (2026-06-11)


### Bug Fixes

* authorize internal release workflow with releaser app ([80b5e19](https://github.com/abaxxtech/agents/commit/80b5e194b02aa499a9b910e8540c1cb1bd681f90))
* verify semantic-release tag generation ([f32769f](https://github.com/abaxxtech/agents/commit/f32769f3714999c1d8c6d09f2482c2d76b950817))
* verify semantic-release tag generation ([0a0ebbe](https://github.com/abaxxtech/agents/commit/0a0ebbeff9e3b530e77b4c2eb7d2806b4533ba49))

# Changelog

All notable changes to this project will be documented in this file.

Starting with 0.11.3, package metadata uses npm-publishable SemVer. Legacy
four-segment human release labels are kept in release headings when needed.
The public npm package identity is `@abaxxlabs/agents`; older changelog
entries may mention pre-public internal package names for historical context.

## [Unreleased]

### Removed

- **Unused `ScopeWarning` error class.** It was defined and exported from the
  internal errors barrel but never thrown, referenced, or tested, and was not
  part of any public entry point or the public-API snapshot. Removing it has no
  effect on consumers.

### Fixed

- **`SqliteRuntimeUnavailableError` is now exported from public subpaths.** The
  error was thrown by `SqliteStorageBackend` but not re-exported from any public
  entry point, so consumers could only match on the message string or error code.
  It is now exported from the main entry (`@abaxxlabs/agents`) and the `./sqlite`
  subpath alongside `SqliteStorageBackend`, so callers can write
  `catch (e) { if (e instanceof SqliteRuntimeUnavailableError) }`.
- **CJS build restored.** Pinned `jose` from 6.2.0 to 5.10.0 and `uuid` from
  14.0.0 to 11.1.1. Both earlier versions were ESM-only, causing
  `SyntaxError: Unexpected token 'export'` when loading the CJS entry point
  (`dist/cjs/index.js`) in standard CommonJS environments. The downgraded
  versions ship dual ESM/CJS builds with identical API surfaces.


### Changed

- **`ScopeEngine` query processing is split into focused internal modules.**
  Credential and delegation authorization now lives in `QueryAuthorizer`, SQL
  execution and column decryption in `QueryRunner`, and audit/result assembly in
  `ResultAssembler`. `ScopeEngine` remains the public orchestration facade, with
  no public API or behavioral change.
- **HTTP credential-issuance integration tests use per-test session capture.**
  The `POST /credentials` route tests previously shared a single mutable
  `capturedOptions` closure across the describe block, which only stayed correct
  under serial execution. Each test now registers its own mock session under a
  unique token and reads its own captured options, so the block is correct under
  concurrent and sharded execution as well. Test-only change; no consumer impact.

- **`engines.node` lowered from `>=22.12.0` to `>=20.3.0`.** The 22.12 floor
  existed only because `jose` 6.x was ESM-only and the CJS build path needed
  `require(esm)` (on by default from Node 22.12). With `jose` pinned to 5.10.0
  (dual ESM/CJS), that constraint no longer applies, so the floor returns to
  `>=20.3.0` to match the platform `id-sdk`. Consumers on Node 20.3+ install
  without an engine compatibility warning.

### Documentation

- **NL-to-SQL claim removed from demo README.** The demo showcase README no longer claims "Natural language to SQL (optional LLM integration)" — NL is an optional demo-side LLM integration (showcase `nl-to-sql.ts`), not a library capability. Documentation only — no behavioural change.
- **Query execution documented as validate-and-execute, not sanitize-and-return.** The MCP `query` tool description and `ScopeEngine.query` JSDoc previously implied queries are "sanitized" and that out-of-scope columns are returned as ciphertext. The engine does not rewrite SQL: it validates the statement (read-only, declared table, projection boundary), executes the original SQL, and returns decrypted rows for in-scope columns. Out-of-scope references are rejected before execution — nothing is returned as ciphertext. Documentation only — no behavioural change.
- **`SELECT *` rejection documented.** The hackathon CHEATSHEET example no longer uses `SELECT *` (always rejected with `ScopeViolationError` — the engine never expands wildcards), and the column-scope story now states the rule explicitly. Documentation only — no behavioural change.
- **Mutation error type clarified in MCP tool docs.** The `query` tool description now states mutations (INSERT/UPDATE/DELETE/DDL) are rejected at parse time with `QueryRejectedError`, distinct from `ScopeViolationError` for out-of-scope column references. Documentation only — no behavioural change.
- **Projection enforcement documented across all column references.** The column-scope story now states that the projection boundary checks every column reference in the statement — SELECT, WHERE, ORDER BY, HAVING, and JOIN ON predicates — not just the SELECT target list, preventing boolean-oracle probes. Documentation only — no behavioural change.
- **Delegation safety documentation now separates issuance-time from query-time enforcement.** The README's delegation narrative previously attributed full chain verification to the ScopeEngine. It now states that subset, TTL, and delegation-depth narrowing is enforced at issuance time, and that at query time the ScopeEngine re-verifies signatures, revocation, depth ceiling, and issuer-subject-owner bindings without re-deriving the subset or TTL narrowing. Delegation chain semantics are described using implemented concepts (supervisor/worker, issuer-subject-owner bindings) instead of a human-vs-agent DID type distinction, which no code path enforces. Documentation only — no behavioural change.
- **MCP HTTP transport auth is documented as bearer-token validation.** The README's MCP + REST section now states that every `GET /sse` and `POST /messages?sessionId=...` request must carry an `Authorization: Bearer <token>` header (RFC 6750), that tokens come from the embedder's `getValidTokens()` callback re-read on every request, and that the `agents mcp` CLI HTTP transport requires `--allow-no-auth` (development/test-only; any other `NODE_ENV` is a startup error). It also clarifies that the `challenge` MCP tool / `POST /challenge` endpoint are for Verifiable-Presentation freshness and replay protection, not transport authentication. The MCP HTTP session-model ADR's stale code reference was corrected. Documentation only — no behavioural change.
- **`IssueCredentialOptions.maxDepth` JSDoc now documents its constraints.** The
  IDE tooltip states the default (2), the valid range (positive integer `>= 1`),
  and that `issueCredential()` throws `maxDepth must be a positive integer` when
  violated. `issueCredential` gained a matching `@throws` entry. Documentation
  only — no behavioural change.

## [0.12.4.0] - 2026-05-26

### Added

- **Showcase Beat 9 — BYOK wrong-key boot panel.** New presenter beat that
  demonstrates the bring-your-own-key loud-fail guarantee end to end. Phase 1
  provisions an encrypted patient row under master key K1; Phase 2 attempts a
  second `AgentScope.create` with K2 and asserts the structured
  `MasterKeyMismatchError` (with `failedCount` and `totalCount` visible to the
  audience) blocks the boot. Wraps up the demo loop with a "Demo Complete" card
  that now lists BYOK loud-fail alongside the rest of the pipeline. Backed by
  the existing `/api/demo/wrong-key` endpoint.

### Changed

- **Showcase narratives no longer time-peg to internal version numbers.** The
  "why it matters" copy for Beat 8 (revocation) and Beat 9 (wrong-key) used to
  say `Pre-v0.9.10.0` / `Post-v0.9.10.0` and similar — refs that confuse a
  non-developer audience and age poorly. Both narratives now contrast a naive
  implementation against this implementation without time-pegging.
- **Beat 8 (revocation) hands off cleanly to Beat 9.** The "Restart Demo ↻"
  button at the end of Beat 8 now reads "Continue →" because Beat 9 is the
  real final beat. The "Demo Complete" wrap-up card moved from Beat 8 to
  Beat 9 and was updated to list BYOK loud-fail in the pipeline summary.

### Fixed

- **Recording mode (`?noadvance=true`) is now honored at the Beat 9 → Beat 1
  loopback.** Previously the auto-advance loopback unconditionally cycled the
  demo back to Beat 1, ignoring `noAdvance` while the linear advance branch
  respected it. The two branches are now consistent — recording mode keeps the
  final beat on screen instead of jumping the camera.

## [0.12.3.0] - 2026-05-22

### Added

- **Showcase: Beat 8 — Credential Revocation.** New presenter-driven panel that
  triggers the existing `/api/demo/revocation` endpoint and renders three
  credentials issued to the same agent: accepted, revoked, accepted. The panel
  shows the agent DID before and after revocation to make clear that revoking
  a credential does not decommission the agent.

- **REST `POST /credentials` and MCP `issue-credential` tool now accept an
  optional `maxDepth` parameter** controlling the delegation chain ceiling
  embedded in the issued JWT. Defaults to the library value (2) when omitted;
  `0`, negative, and non-integer values are rejected with HTTP 400. Closes the
  gap from where only the in-process SDK accepted this parameter.
  OpenAPI spec and MCP `rest-bridge` tool descriptors updated to surface the
  new field.

### Changed

- **Showcase: Beat 7 wording.** Replaced the now-incorrect "Demo Complete" card
  and "You've seen the full pipeline" copy with a scoped "Cross-Org Verified"
  card. Beat 7 is no longer the final beat.
- **Showcase: StatusBar.** The header counter now renders `Beat X/{BEATS.length}`
  instead of a hardcoded `/7`, so future beats no longer leave a stale denominator.

## [0.12.2.0] - 2026-05-21

### Fixed

- **`issueCredentialWithSdk` now embeds caller-specified `maxDepth` in the
  issued JWT.** Previously the `credentialData` object omitted `maxDepth`,
  so credentials issued through the SDK path silently received the library
  default (2) regardless of what the caller passed. The parent-provider path
  (`issueCredentialFromParent`) now forwards `maxDepth` to the parent API as
  well.

## [0.12.1.0] - 2026-05-20

### Fixed

- **CJS build no longer crashes on `require('@abaxxlabs/agents')`.** The
  `jose` 6.x migration landed an ESM-only dependency that the CJS build path
  cannot `require()` on Node versions without `require(esm)` support. The
  package now advertises `engines.node: ">=22.12.0"`, where `require(esm)` is
  on by default. Verified against all seven public subpaths.

### BREAKING

- **`engines.node` raised from `>=20.3.0` to `>=22.12.0`.** Required because
  `jose` 6.x is ESM-only and the CJS build path needs `require(esm)`, which
  is on by default starting in Node 22.12. Node 20 LTS reached end-of-life
  on 2026-04-30, so the supported floor moves up with the runtime. CI now
  tests only on Node 22; `actions/setup-node` pins updated accordingly.

## [0.12.0.0] - 2026-05-20

### Performance

- **JWT signer/verifier reuses imported `CryptoKey` across calls.**
  migrated `jwt-utils.ts` from `node:crypto` to `jose`, but every `createJwt`
  and `verifyJwtSignature` call invoked `importJWK()` from scratch, allocating
  a fresh WebCrypto `CryptoKey` each time. `createJwt` additionally re-ran
  `ed25519.getPublicKey()` (a scalar multiplication) on every signature. Both
  paths now cache the imported `CryptoKey` in a bounded LRU (cap 256) keyed by
  the raw key bytes. A signer that loops over 100 signatures with the same
  private key now calls `importJWK` once; a verifier that processes 50
  credentials from the same issuer calls `importJWK` once for that public
  key. Closes

### Fixed

- **`connectIdSdkMcp()` now works on a fresh `npm install`.**
  The vendored id-sdk-mcp server's 33 transitive dependencies (`multiformats`,
  `libp2p`, `ethers`, `ion-sdk`, etc.) used to live in
  `vendor/id-sdk-mcp/node_modules` and were excluded from the published
  tarball, leaving consumers to run a manual `bun install` before the MCP
  surface would load. They are now declared on the root package, so a single
  `npm install @abaxxlabs/agents` is sufficient. `level` and
  `@mattrglobal/bbs-signatures` are listed under `optionalDependencies` so the
  package still installs on platforms where those native builds fail; if they
  are absent, `connectIdSdkMcp()` throws a pointed error naming the missing
  dep instead of an opaque `ERR_MODULE_NOT_FOUND`.

### Changed

- **Audit records are always V3.** New records no longer fall back to V2 when
  `orgId` is absent. The versioned hash function still handles V1/V2 for chain
  verification of pre-launch records.
- **Credential issuance JSDoc rewritten.** `issueCredential` is the local-key
  path, not a "legacy fallback." `issueCredentialWithSdk` is the SDK-enhanced
  path. Both are first-class.
- **Install footprint grows for the id-sdk-mcp surface.** Hoisting the 33
  vendor dependencies onto the root package means every consumer of
  `@abaxxlabs/agents` now pulls them, including consumers that do not call
  `connectIdSdkMcp()`. This is the agreed trade-off for out-of-the-box
  install; the alternative was a separate `@abaxxlabs/id-sdk-mcp-server`
  companion package.
- **`@modelcontextprotocol/sdk` promoted from `optionalDependencies` to
  `dependencies`.** Both the `./mcp` adapter and the new id-sdk-mcp surface
  fail hard without it; declaring it optional was inconsistent with that
  reality. The previous "optional" flag only suppressed install failures
  from the MCP SDK itself — npm/bun installed it by default, so this change
  is a no-op for consumers on supported platforms.

### Removed

- **`AgentScope` wrong-subpath guard deleted from root entry point.**
  Pre-launch, no consumer imports `AgentScope` from `@abaxxlabs/agents`; the
  `@deprecated` Proxy that threw on use was vestigial.

### Security

- **Audit logger fails closed unconditionally**. The `failOpen`
  option is removed from `AgentScopeConfig.audit` and `AuditLogger`. Any audit
  store append failure now throws `AuditWriteFailedError` and the calling
  operation rejects — no opt-in escape hatch. HIPAA §164.312(b), SOC 2 CC7.2,
  and GDPR Art. 32 all require persistent audit records; the prior opt-in path
  was a regulatory red flag for an identity-guardrails product.
- **JWT private-key cache key is a SHA-256 digest, not raw base64url bytes.**
  The signing-side `CryptoKey` cache hashes the private key bytes before using
  them as a `Map` key, so process memory never holds a printable copy of the
  raw private key for the lifetime of the cache entry. The pre-existing copies
  in caller closures (e.g., `createSigner`) are unchanged; this just avoids
  widening the attack surface for memory disclosure.
- **JWT verifier caches public keys only after `compactVerify` succeeds.** The
  verify-side cache previously inserted on import, so an attacker submitting
  256 VPs with bogus signatures could evict legitimate issuer keys and force
  re-imports. Cache writes are now gated on a successful signature check.

### BREAKING

- **Legacy `encryption-only-LEGACY-DO-NOT-USE` scopeMode deleted.**
  `ScopeMode` is now the literal `'projection'`; the legacy type, the
  `AGENTS_ALLOW_LEGACY_SCOPE_MODE` env gate, and
  `LegacyScopeModeNotAllowedError` are removed. All credentials must include
  every column referenced in SQL (plaintext and encrypted). Demo user-stories
  updated to projection-mode scopes.
- **`SqliteStorageBackend` requires `sessionMacKey` unconditionally**. The zero-key fallback (`Buffer.alloc(32, 0)`) is removed. Callers must
  pass an HKDF-derived `sessionMacKey` via the `backendOpts` parameter.
  Use `deriveSessionMacKey(masterKey)` from `@abaxxlabs/agents` to derive the
  key. Construction without a key now throws `TypeError`.
- `AgentScopeConfig.audit.failOpen` removed. Consumers passing
  `audit: { failOpen: true }` must drop the field; `audit: { enabled: true }`
  is now sufficient.
- `AuditLogger` constructor option `failOpen` removed.
- `AuditWriteFailedError` constructor signature changed from
  `(reason: string, failOpen: boolean)` to `(reason: string)`.
- `AuditLoggerTelemetrySink.auditWriteFailed` event shape lost the `failOpen`
  field.

- **Legacy AbaxxOne OIDC entry points deleted** ( closeout).
  `src/auth/legacy-oidc.ts` and `src/auth/verified-auth-state.ts` are removed.
  The module-level functions `authenticateWithOidc`, `completeOidcFlow`, and the
  `VerifiedAuthState` brand machinery no longer exist. `AgentIdentity` delegates
  all AbaxxOne OIDC flows through `AbaxxOneOidcProvider`. The public auth barrel
  no longer exports `verifyAuthState`, `CsrfStateRejectedError`,
  `VerifiedAuthState`, or `OidcConfig`. Supersedes
- **Legacy `scopeMode` construction gate**. `AgentScope.create` / `loadConfig` now throw `LegacyScopeModeNotAllowedError` when `scopeMode` is `encryption-only-LEGACY-DO-NOT-USE` unless `AGENTS_ALLOW_LEGACY_SCOPE_MODE=1` is set. `getServerStatus()` includes `scopeMode` (defaults to `projection` when omitted from config).

### BREAKING

- `AgentIdentity.completeAuthentication` and `AgentScope.completeAuthentication`
  now require the OAuth `state` parameter from the callback, positionally
  between `authorizationCode` and `codeVerifier`:
  ```ts
  // Before
  await scope.completeAuthentication(code, codeVerifier);
  // After
  await scope.completeAuthentication(code, state, codeVerifier);
  ```
  The `state` is validated against a per-instance `PendingFlowStore` opened
  by the matching `authenticate()` call. Mismatch, expiry, or PKCE verifier
  mismatch raises `CsrfStateRejectedError` before any network exchange.

- **`AgentScopeConfig.delegation` and `AgentIdentityConfig.delegation` removed.**
  Pass `maxDepth` directly on `IssueCredentialOptions` when calling
  `issueCredential()`. The depth ceiling is now embedded in the root credential
  at issuance and inherited automatically by all downstream delegations.
  ```ts
  // Before
  const scope = await AgentScope.create({ delegation: { maxDepth: 1 }, ... });
  // After
  const vc = await scope.issueCredential({ maxDepth: 1, ... });
  ```

- **`issueDelegatedCredential` no longer accepts `operatorMaxDepth`.**
  The delegation depth ceiling is inherited from the parent credential's
  embedded `maxDepth` field. Callers that passed `operatorMaxDepth` must remove
  the parameter; the ceiling is set by the human issuer at root credential
  issuance time and propagated automatically.

### Changed

- CLI commands no longer accept `--master-key <hex>` or `--master-key=<hex>`.
  Use `AGENTS_MASTER_KEY` in the process environment or pipe a key with
  `--master-key-stdin`.

### Fixed

- `--master-key-stdin` now rejects interactive TTY stdin with guidance and caps
  input at 1 KiB before parsing.
- `agents serve` now builds its child-process environment through a tested
  helper, preserving inherited `AGENTS_MASTER_KEY` without dead option logic.

## [0.11.6.0] - 2026-05-12

### Fixed

- **TTL violations now produce HTTP 400 instead of 500.** `assertExpiresInBound`
  was duplicated across `session-factory.ts` and `transport/validation.ts` with
  divergent error types — the session-factory copy threw a bare `Error` that
  bypassed the transport error mapper. Single canonical implementation in
  `config.ts` now throws `TtlExceededError` (code `TTL_EXCEEDED`), mapped to 400.

- **Resolved CodeQL polynomial-ReDoS alerts.** Bounded `parseDuration` regex
  quantifiers (`\d+` → `\d{1,20}`) and added 64-char input length guard.
  Fixed pre-existing alerts in `jwt-utils.ts` (`/=+$/` → `/={1,2}$/`) and
  `sql/index.ts` (replaced regex with `indexOf`/`slice` for connection string
  credential masking).

### Added

- `TtlExceededError` exported from public API (extends `AgentScopeError`).

## [0.11.4] - 2026-04-30 — Architecture decomposition (release label 0.11.4.0)

Four audit-flagged files (scope-engine.ts, vc-verifier.ts, auth/agent.ts,
storage/types.ts) decomposed into single-responsibility modules. All public
imports preserved via barrel re-exports. No behavioral changes.

### Refactored

- **scope-engine.ts split**. SQL query validation
  extracted to `src/sql/query-policy.ts`; delegation validation extracted to
  `src/sql/delegation-policy.ts`. scope-engine.ts is now orchestration-only.
- **vc-verifier.ts split**. JWT parsing/signing extracted to
  `src/jwt-utils.ts`; DID resolution and caching extracted to
  `src/did-resolver.ts`. vc-verifier.ts now handles credential verification only.
- **auth/agent.ts split**. Decomposed into `agent-crud.ts`,
  `credential-issuance.ts`, `session-factory.ts`, and `did-key.ts`. Barrel
  re-exports preserve the `auth/agent.js` import path.
- **storage/types.ts split**. Storage interfaces decomposed into
  `audit-store.ts`, `revocation-store.ts`, `session-store.ts`, and
  `storage-backend.ts`. Barrel re-exports preserve the `storage/types.js` path.
- **IdSdkInstance converged**. Replaced weak `any`-typed inline
  interface in `types.ts` with strongly-typed canonical definition in
  `src/id-sdk-types.ts`. MCP adapter uses type assertions at transport boundary.
- **legacy-oidc.ts marked `@deprecated`**. Target removal: v1.0.

### Added

- **Branded domain types**. `Did`, `ColumnName`, `TableName`,
  `Jti`, `IssuerUrl` in `src/domain-types.ts` with factory functions for
  boundary validation.
- **Architecture guidelines in CLAUDE.md**. 500-line file limit,
  single responsibility, policy vs orchestration split, strategy over branching,
  domain types at boundaries, Result types, no env reads in library code.
- **Test coverage for extracted modules.** `did-cache.test.ts` (5 tests),
  `query-policy.test.ts` (14 tests), `domain-types.test.ts` adversarial cases,
  `delegation-policy.test.ts` zero-expiry edge case.

### Fixed

- **`generateDidKeyFromSeed` removed from public API surface.** Was inadvertently
  exported during auth/agent.ts decomposition; barrel now uses named exports to
  keep it internal.
- **`base64UrlDecode`/`base64UrlEncode` unexported.** Adversarial review caught
  unnecessary export widening in jwt-utils.ts; now module-private.

## [0.11.3] - 2026-04-29 — Release readiness gates (release label 0.11.3.0)

`import.meta` is a syntax-level construct that V8 rejects at parse time inside
CJS modules. The previous code placed it behind a try/catch, but the CJS loader
fails before any runtime code executes. The `/sql` and `/mcp` subpaths (which
transitively import `storage/postgres`) were unusable under `require()`.

### Fixed

- **CJS `SyntaxError` on `/sql` and `/mcp` subpaths**.
  Replaced the bare `import.meta.url` access in `src/storage/postgres/index.ts`
  with an indirect `eval` that defers parsing to runtime. CJS consumers never
  reach the eval (they resolve `__dirname` first); under ESM the eval also
  throws (Script context cannot access `import.meta`) and falls through to
  `process.cwd()`. All six subpaths now load under both CJS and ESM.
- **Published package bin artifact restored**. The build no
  longer deletes `dist/cli`, so the documented `agents` npm bin points at a
  real tarball artifact after a clean build.
- **Stale test assumptions cleaned up**. Tests now assert the
  current wrong-master-key behavior and the current `src/sql` scope-engine path
  instead of older source-layout assumptions.

### Added

- **CI smoke test for CJS + ESM subpath loading.** `npm pack` + fresh-consumer
  `require()` and `import()` of every subpath runs on every PR. Catches
  packaging regressions that vitest (ESM source mode) cannot.
- **Package metadata artifact assertion**. CI now fails when
  `main`, `module`, `types`, `exports`, or `bin` references a missing build
  artifact, and the tarball smoke test verifies installed npm bins as well as
  package subpaths.
- **npm cache ownership guard**. Release verification now checks
  npm cache ownership before pack, publish dry-run, and tarball smoke installs.
- **Public artifact audit**. Package artifacts and
  explicit public-repo candidate roots/lists can now be audited for forbidden
  internal paths, oversized text files, and high-confidence secret patterns.
- **Deterministic default test gate**. Keychain, loopback HTTP,
  and local Abaxx One tests are excluded from default `npm test` and remain
  available through the explicit e2e command with opt-in environment variables.
- **REST/MCP shared API ADR**. The release plan now records
  transport-neutral services, shared validation, shared errors, shared rate
  limits, and MCP dependency narrowing as the preferred implementation path.
- **Public API snapshot gate**. CI now snapshots exported names
  for the six supported package subpaths: root, `/sql`, `/mcp`, `/storage`,
  `/sqlite`, and `/bootstrap`.
- **MCP no-peer import smoke test**. Fresh tarball consumers now
  import `@abaxxlabs/agents/mcp` under both CJS and ESM without manually adding
  SQL peers; SQL-backed startup paths still name the required peer set.

### Changed

- **AbaxxLabs public package identity pinned**. Active package
  metadata, registry config, public docs, release smokes, server/scaffold
  consumers, and showcase demo imports now target `@abaxxlabs/agents` on the
  public npm registry.
- **Public package dependencies pinned for release**. Runtime,
  optional, and peer dependency ranges are exact-pinned to the audited
  lockfile versions for 0.11.3.

## [0.11.2.0] - 2026-04-29 — Branded migration credential types

Compile-time trust verification for migration credentials. Branded types
(`TrustedMigrationCredential`, `VerifiedParentCredential`) give TypeScript
callers a type-level guarantee that the migration trust check passed before
`MigrationExecutor.execute()` is called. The runtime trust gate is preserved
as the actual security boundary (brands are erased at compile time).

### Added

- **Branded types `TrustedMigrationCredential` and `VerifiedParentCredential`.**
  Nominal types constructed only via smart constructors. Prevents accidental
  use of unverified JWT strings in migration paths at compile time.

- **Smart constructors `asTrustedMigrationCredential()` and
  `asVerifiedParentCredential()`** decode the JWT issuer, check it against
  `MigrationTrustAnchor`, and return the branded type or throw
  `UntrustedMigrationIssuerError`.

- **`decodeJwtIssuer()` exported from `migration-trust-anchor.ts`.**
  Extracts the `iss` claim from a compact JWS without signature verification.
  Previously a private function in `migration.ts`; now shared by both smart
  constructors and the runtime gate.

- **`MigrationExecutor.migrationTrustAnchor` getter.** Lets callers pass the
  executor's anchor to the smart constructor:
  `asTrustedMigrationCredential(jwt, executor.migrationTrustAnchor)`.

- **Brand-bypass regression test.** Verifies the runtime gate still fires when
  a caller uses `as TrustedMigrationCredential` to bypass the compile-time
  brand, and confirms `pool.connect` is never called on untrusted input.

### Changed

- **`MigrationExecutor.execute()` param type narrowed** from `string` to
  `TrustedMigrationCredential`. TypeScript callers must use the smart
  constructor; the runtime gate is retained as defense-in-depth for JS callers
  and `as`-cast bypasses.

- **Cleaned Jira ticket references from code comments.** Removed
  project-specific ticket IDs from test describe blocks and inline comments
  to keep documentation audience-neutral.

## [0.11.1] — Internal pre-public — Hackathon-finding follow-ups

A small follow-up release closing three loose ends from the hackathon-finding
arc and adversarial review on PR #24. Pure additions and a bug fix; no
breaking changes.

### Added

- **`parseDuration` accepts compound, fractional, and millisecond strings
.** Previously rejected anything that did not match
  `/^(\d+)(s|m|h|d)$/`. Now accepts `'500ms'`, `'1.5s'`, `'1m30s'`,
  `'2h15m'`, `'1.5d'`, etc. Bare numbers, unknown units, trailing garbage,
  and duplicate units (`'1m1m'`) still throw. Purely additive — existing
  callers (`clockSkew`, `resolverCacheTtl`, VP `lifetime`) are unaffected.

- **`CreatePresentationOptions.audience` accepts `string | string[]`
.** Single DID for point-to-point presentation, array for
  multi-verifier scenarios (multi-region, primary + failover). Per RFC 7519
  §4.1.3, `aud` MAY be a string or array of case-sensitive strings — the
  verifier already handled both shapes; this widens the signer to match.

### Fixed

- **`verifyAuditChain()` no longer always returns `ok: false` on filtered
  subsets.** The verification algorithm previously required
  the first record's `previousHash` to equal `'GENESIS'`, so any call with
  an `agentDid`, `since`, or `orgId` filter that started mid-chain returned
  `ok: false` regardless of tampering. Filtered calls now anchor at the
  first record's `previousHash` and verify forward; the return type gains
  a `partial: boolean` flag so callers know whether full root-of-chain
  verification was performed. JSDoc documents the residual limitation that
  `agentDid` / `orgId` filters may produce non-consecutive subsets, in
  which case an apparent break may reflect a gap in the filtered view
  rather than tampering — call without a filter for absolute root-of-chain
  proof.

- **`parseDuration` rejects out-of-range values (~100-year cap).** Cross-
  model adversarial review on PR #41 (Codex + Claude) flagged that huge
  inputs like `'99999999999d'` produced numbers above
  `Number.MAX_SAFE_INTEGER` or `Infinity`. Without a cap, `clockSkew`
  fed such a string would have allowed expired credentials to be accepted
  indefinitely; `lifetime` on `createPresentation` would have produced a
  garbage VP `exp`; values fed to `setTimeout` are silently clamped to
  `1ms` per the HTML spec. `parseDuration` now throws on any duration
  above ~100 years, on `Infinity`, and on negative results.

- **`AuditLogger.export()` and `verifyAuditChain()` preserve `orgId`
  through alias expansion.** Pre-existing bug surfaced during Codex
  review of: when the alias-expansion branch fired (a
  migrated agent with multiple equivalent DIDs in the registry), the
  rebuilt store query silently dropped `orgId`. An operator running
  `verifyAuditChain({ agentDid, orgId: 'org-A' })` against an agent
  whose aliases lived in different orgs would have seen cross-org
  records, corrupting org-scoped compliance verification. Fixed.

### Reverted

- ** branded migration credential types (commit `123a84d`).**
  First implementation correctly added `TrustedMigrationCredential` /
  `VerifiedParentCredential` branded types and smart constructors, but
  deleted the runtime defense-in-depth trust check from
  `MigrationExecutor.execute()` in service of the type contract. Branded
  types are erased at compile time; JS callers, `as` casts, and any future
  RPC bridge that constructs the call dynamically would have bypassed the
  gate. Reverted in commit `10fc575`. Redo planned as additive: keep the
  runtime check AND add the brands. Full plan: `docs/-redo-plan.md`.

## [0.11.0] — Internal pre-public — AgentScope / AgentIdentity split

### Breaking changes

- **`AgentScope` moved to `@abaxxlabs/agents/sql`.** The main entry
  (`@abaxxlabs/agents`) no longer exports `AgentScope`, `ScopeEngine`,
  `ScopeMode`, `SCOPE_MODE_LEGACY`, or SQL-specific column-key functions.
  Update imports: `import { AgentScope } from '@abaxxlabs/agents/sql'`.

- **`AgentIdentity` is the new primary class** exported from the main entry.
  It provides DID generation, credential issuance, agent registration, OIDC
  authentication, and audit — without any dependency on `pg` or SQL. Non-SQL
  consumers (MongoDB, GraphQL, etc.) can use the full identity layer.

- **MCP server moved to `@abaxxlabs/agents/mcp`.** `createMcpServer` and
  `connectStdio` are no longer re-exported from the main entry.

- **`libpg-query` moved to optional peerDependencies.** Consumers using the
  SQL subpath must install it directly. Pinned at `17.7.3`.

- **`AgentIdentity` interface renamed to `RegisteredAgent`.** The old name
  conflicted with the new `AgentIdentity` class. All code referencing the
  agent-record interface should use `RegisteredAgent`.

### Added

- **`AgentIdentity` class** (`src/agent-identity.ts`) — SQL-free identity,
  auth, and agent management. Factory-tuple pattern: `create()` for public
  use, `_createWithInternals()` for AgentScope composition.

- **6 subpath exports**: `.`, `./sql`, `./mcp`, `./storage`, `./sqlite`,
  `./bootstrap`.

- **`AgentStore.listAll()` and `AgentStore.count()`** — new methods on the
  storage backend interface for boot-time agent restore and dashboard stats.

- **`AuditStore.count()`** — count audit records without loading them.

- **Import isolation test** — acceptance criterion verifying the main entry
  loads neither `pg` nor `libpg-query` at import time.

### Changed

- Auth functions (`createMockSession`, `createOidcSession`,
  `createSessionFromDid`) no longer accept a `pool` parameter. The unused
  `_pool` params have been removed.

- `createAgent` and `restoreAgents` now accept `AgentStore` instead of
  `Pool`. Domain logic (key wrapping, signer creation) stays in the auth
  functions; only persistence is delegated to the store interface.

- `AuditLogger` no longer depends on `Pool`. It writes through `AuditStore`.

- `ScopeEngine` takes an `agentStore: AgentStore` param for owner-lookup
  fallback. `pool.query` is used solely for data-plane query execution.

## [0.10.1] — Internal pre-public — VP lifetime tightening

A focused patch sized at a QA finding from the hackathon dry-run: the
`createPresentation()` default expiry of 300s was a five-minute first-mover
replay window for any captured VP. The `seenJtis` cache catches the *second*
redeem of a captured presentation, not the first — so the VP's `exp` IS the
attack window. At machine-speed RPC, five minutes is far longer than the
operation needs.

### Behavior change

- **`createPresentation()` default lifetime tightened from `300s` to `60s`.**
  60s is generous for a single agent → verifier → response cycle and 5×
  tighter than the prior default. Consumers needing the old window
  (human-in-the-loop flows, resumable sessions where a VP may sit in a UI
  before redemption) now pass `lifetime: '5m'` explicitly. The reverse — tight
  default with opt-in for longer — pushes the security-conscious choice to
  the default and forces a deliberate decision when a longer window is wanted.

### Added

- **`CreatePresentationOptions.lifetime?: string`** — new optional duration
  string (e.g. `'30s'`, `'5m'`) controlling VP expiry. Parsed by the existing
  `parseDuration` helper for consistency with `clockSkew` and other library
  durations. Accepted format is `NN<unit>` where unit is one of `s|m|h|d`
  and `NN` is a positive integer; minimum lifetime is 1 second. Malformed
  values and zero lifetimes throw at call time rather than producing a VP
  with an invalid or near-instantly-expired `exp` that would only fail
  downstream at verify().

### Documentation

- **`VcVerifierOptions.clockSkew` JSDoc expanded.** Spells out that the single
  `clockSkew` knob is applied symmetrically to BOTH credential and presentation
  timestamp checks (VC `nbf`/`exp` and VP `nbf`/`exp`) and also extends the
  JTI replay-cache TTL by `clockSkew` past `exp`. Closes the doc gap exposed
  during hackathon QA — reviewers had to read the verify path to discover
  the symmetric coverage.

### Acknowledgements

QA flagged the 30s `clockSkew` as a concern only for very
short-lived credentials during the hackathon dry-run. Investigation
surfaced the larger architectural decision: VP lifetime, not skew, was the
load-bearing knob — and it was hardcoded.

## [0.10.0] — 2026-04-26 — Session 7 / Library-shrink follow-up

Session 7 — eight sub-tasks promoting the remaining implicit
library env-reads to explicit consumer-supplied configuration. v0.10.0 closes
the library-shrink arc: post-Session-7, the library reads exactly two env vars
inside `src/` (`NODE_ENV` and `CI` — both intentional runtime-shape gates,
documented in `docs/internal/support-runbook-v0.9.10.0.md` § "Environment variables
read by the library"). The five Session-6-era `AGENTS_*` env-reads are gone.

### Breaking changes

- **`createKeystore` signature is now an options object.** Was
  `createKeystore(customPath?: string)`; now `createKeystore(opts?: { customPath?: string; devMode?: boolean })`.
  Migration: `createKeystore('/p')` → `createKeystore({ customPath: '/p' })`.
  Only callers in this repo are tests; external consumers that called the
  factory directly with a string argument must update.
- **Library no longer reads `AGENTS_DEV_MODE` from the environment.** Promoted
  to `AgentScopeConfig.devMode?: boolean`. Bridge from env at the consumer
  boundary: `devMode: process.env.AGENTS_DEV_MODE === 'true'`. `NODE_ENV`
  gates remain in place inside the library (defense-in-depth — `NODE_ENV !==
  'production'` is the runtime gate against booting mock auth in prod).
- **Library no longer reads `AGENTS_KEYSTORE_PATH` from the environment.**
  The fallback inside `createKeystore` was removed. Path now comes
  exclusively from the `customPath` option; bridge at the consumer boundary
  with config-first precedence: `createKeystore({ customPath: config.keystore?.path ?? process.env.AGENTS_KEYSTORE_PATH })`.
  Promoted to `AgentScopeConfig.keystore?: { path?: string }` for consumers
  that prefer config-blob-driven configuration. *No first-party consumer
  impact in this repo* — `packages/server`, `src/mcp`, and the scaffold all
  use ephemeral did:key per process and never call `createKeystore`. External
  SDK consumers that called `createKeystore` directly with a string argument
  (or relied on the env fallback) must migrate.
- **Library no longer reads `AGENTS_CONSUMER_DOMAINS` from the environment.**
  Pre-v0.10.0 the env var was read at TWO independent library sites
  (`src/identity/org-boundary.ts` and `src/auth/generic.ts`) — a
  misconfiguration could produce inconsistent boundaries between the two
  engines. The two engines also maintained different built-in domain lists
  (`GenericOidcProvider` had a 12-entry subset; `OrgBoundary` had ~21).
  v0.10.0 unifies the source: `OrgBoundary.extract()`,
  `OrgBoundary.assertMembership()`, `OrgBoundary.isConsumerEmail()` each
  accept an optional `extraConsumerDomains?: readonly string[]` parameter;
  `GenericOidcProvider` accepts `extraConsumerDomains` as a constructor
  option; `createBindingCredential` accepts it via `BindingOptions` so the
  binding VC's `orgDomain` field reflects the same policy. All four call
  paths use the same newly-exported `composeConsumerDomains()` helper.
  Promoted to `AgentScopeConfig.orgBoundary?: { extraConsumerDomains?: string[] }`.
  Bridge env at the consumer boundary and pass the SAME list to all
  engines. **Behavior change:** because the unified list is the larger
  `OrgBoundary` set, emails at `msn.com`, `yahoo.co.uk`, `yahoo.fr`,
  `yahoo.de`, `tutanota.com`, `tutamail.com`, `zoho.com`, `mail.com`, and
  `inbox.com` now correctly return undefined from `GenericOidcProvider`'s
  email-domain fallback (pre-v0.10.0 they incorrectly produced an org).
  Sessions previously authenticated via these domains will fail org
  assertions post-upgrade — by design, the prior behavior was unsafe.
- **Library no longer reads `AGENTS_TRUSTED_SERVERS` from the environment.**
  The env-read inside `LocalTrustAnchorStore`'s constructor was removed.
  Trust anchors are security-critical posture decisions; sourcing them at
  the consumer boundary makes the flow auditable. The new shape:
  `LocalTrustAnchorStore({ ownServerDid, initialTrustedServers })`. Bridge
  from env at the consumer boundary using the new bootstrap helper:
  ```ts
  import { resolveTrustedServersFromEnv } from '@abaxxlabs/agents/bootstrap';
  const initialTrustedServers = resolveTrustedServersFromEnv();
  ```
  Mirrors the `AGENTS_MASTER_KEY` / `resolveMasterKeyFromEnv()` pattern.
  *No first-party consumer impact in this repo* — `packages/server`,
  `src/mcp`, and the scaffold do not currently instantiate
  `LocalTrustAnchorStore`. External SDK consumers that previously relied on
  `AGENTS_TRUSTED_SERVERS` env-loading inside their `LocalTrustAnchorStore`
  construction MUST migrate to the bootstrap helper.
- **Library no longer reads `AGENTS_ALLOW_LEGACY_SCOPE_MODE` from the
  environment.** The env-coupled gate (added in) was removed.
  The legacy `ScopeMode` value was renamed from `'encryption-only'` to
  `'encryption-only-LEGACY-DO-NOT-USE'` — the verbose value name preserves
  the "make this annoying to opt into" friction the env var previously
  provided. Two migration steps for consumers using legacy scope mode:
  (1) drop the `AGENTS_ALLOW_LEGACY_SCOPE_MODE=true` env-set; (2) update
  `scopeMode: 'encryption-only'` config-blob references to the verbose
  value. The `SCOPE_MODE_LEGACY` constant is exported as a typed convenience
  for consumers that prefer not to type the literal string. The `'projection'`
  default mode is unaffected.

### Added

- `AgentScopeConfig.devMode?: boolean` — explicit dev-mode opt-in. When
  `true`, the validator allows a config without `abaxxOne` or `oidc` (mock-auth
  path). Independent of `createKeystore({ devMode })`, which is consumer-side
  for the same flag's keystore-prompt-skip effect.
- `AgentScopeConfig.keystore?: { path?: string }` — explicit keystore path
  configuration. Round-trips through `loadConfig` unchanged. Library code
  does NOT internally call `createKeystore` (it's a consumer surface);
  consumers thread `config.keystore?.path` into `createKeystore({ customPath })`.
- `composeConsumerDomains(extraConsumerDomains?)` exported from
  `@abaxxlabs/agents` — pure helper that composes the built-in consumer-domain
  registry with caller-supplied extensions. Used internally by both
  `OrgBoundary` and `GenericOidcProvider` to guarantee they share a single
  source of truth (the v0.9.x dual-read divergence is structurally fixed).
- `resolveTrustedServersFromEnv()` exported from `@abaxxlabs/agents/bootstrap`
  — returns parsed `string[]` from `AGENTS_TRUSTED_SERVERS` (comma-separated,
  trimmed, deduped). Format-agnostic (no DID-method validation). Pass the
  result to `LocalTrustAnchorStore({ ..., initialTrustedServers })`. The
  pre-v0.10.0 env-read inside the library is gone.
- `LocalTrustAnchorStore({ initialTrustedServers })` constructor option —
  explicit list of pre-trusted issuer DIDs. Replaces the prior implicit
  `AGENTS_TRUSTED_SERVERS` env-load. The 'env' source label is preserved on
  loaded anchors for audit-trail continuity.
- `SCOPE_MODE_LEGACY` constant exported from the main entrypoint —
  `'encryption-only-LEGACY-DO-NOT-USE'` typed as `ScopeMode`. Consumers can
  `import { SCOPE_MODE_LEGACY } from '@abaxxlabs/agents'` instead of typing
  the literal string.
- `agents migrate-check` now emits advisory sections for
  `process.env.AGENTS_DEV_MODE`, `process.env.AGENTS_KEYSTORE_PATH`, and
  `process.env.AGENTS_ALLOW_LEGACY_SCOPE_MODE` reads, with bridging recipes
  pointing at the corresponding `AgentScopeConfig` fields. Independent of the
  four BYOK migration cases (which keep their v0.9.10.0 definitions).

### Changed

- `packages/server/src/index.ts`, `src/mcp/index.ts`, and the
  `npm create @abaxxlabs/agents` scaffold (`packages/create-agents/template/src/index.ts`)
  all bridge `AGENTS_DEV_MODE` from env at their own boundaries with a
  `NODE_ENV !== 'production'` fallback (audit Matrix 3 row 3). Existing
  `NODE_ENV` security gates inside the library are untouched.

### Sub-tasks

- — LIB-CONFIG: `AGENTS_DEV_MODE` → `AgentScopeConfig.devMode`.
- — LIB-CONFIG: `AGENTS_KEYSTORE_PATH` → `AgentScopeConfig.keystore.path`.
- — LIB-CONFIG: `AGENTS_ALLOW_LEGACY_SCOPE_MODE` removed; `ScopeMode` legacy value renamed to `'encryption-only-LEGACY-DO-NOT-USE'`.
- — LIB-MIGRATE: `AGENTS_TRUSTED_SERVERS` → `resolveTrustedServersFromEnv()` bootstrap helper + `LocalTrustAnchorStore({ initialTrustedServers })` constructor option.
- — LIB-MIGRATE: `AGENTS_CONSUMER_DOMAINS` → `AgentScopeConfig.orgBoundary.extraConsumerDomains` + `OrgBoundary.*(...,extraConsumerDomains?)` static-method param + `GenericOidcProvider({ extraConsumerDomains })` constructor option. Dual-read surface unified.
- — DOCS: `NODE_ENV` and `CI` documented as library-implicit env reads. Both retained intentionally — `NODE_ENV` is a defense-in-depth runtime gate against booting mock auth in production; `CI` is a universal CI convention that lets the keystore skip the macOS Keychain prompt unattended. JSDoc on the four read sites (`src/auth/agent.ts`, `src/index.ts`, `src/auth/discovery-utils.ts`, `src/identity/keystore.ts`) cross-references the new "Environment variables read by the library" section in `docs/internal/support-runbook-v0.9.10.0.md`.
- — OBS: MCP CLI now emits a structured `WARNING` at startup when booting with `NODE_ENV=production` and no explicit `injections.storage` (the default-backend path has cross-instance revocation coherency poll OFF). Mirrors the API server's `SESSION_STORE_MODE=dual` warning pattern. New `docs/internal/support-runbook-v0.9.10.0.md` § "MCP multi-instance revocation coherency" explains the trade-off and migration path for operators running multi-instance MCP.
- — TESTS: new `test/regression/env-isolation.test.ts` is the unified regression suite asserting the post-Session-7 contract that the library does NOT read any of the five migrated `AGENTS_*` env vars (`AGENTS_DEV_MODE`, `AGENTS_KEYSTORE_PATH`, `AGENTS_ALLOW_LEGACY_SCOPE_MODE`, `AGENTS_TRUSTED_SERVERS`, `AGENTS_CONSUMER_DOMAINS`). 11 tests covering both directions for each variable (env set + no consumer wiring → env content does NOT leak; env set + EXPLICIT consumer wiring with different value → env loses, explicit wins) plus a cross-cutting "all 5 set simultaneously" worst-case scenario. Catches drift if a future maintainer reintroduces any env-read.

## [0.9.10.0] — 2026-04-25 — Session 6 / Library-shrinking arc complete

### Security posture

- **Revocation enforcement gap (pre-existing, v0.9.6.0–v0.9.9.x)**: versions v0.9.6.0 through v0.9.9.x advertised an injection path for `IRevocationStore` that no code implemented; all deployments ran on process-local in-memory revocation. The `IRevocationStore` interface and three adapters (`InMemoryRevocationStore`, `SqliteRevocationStore`, `PostgresRevocationStore`) shipped in v0.9.6.0, but `AgentScope.create` had no parameter to receive an injected store — the `VcVerifier` silently defaulted to `InMemoryRevocationStore` in every deployment. Multi-instance deployments and deployments relying on cross-restart durability were enforcing revocation only within a single process lifetime. This release wires the injection path (via the new `injections` parameter), structurally prevents recurrence (the type system now rejects a `VcVerifier` constructed without a `revocationStore`), and ships a default `PostgresRevocationStore` wiring in `packages/server/` when `DATABASE_URL` is set. **If you operate multi-instance or rely on revocation durability across restarts, read `docs/migrations/byok.md` before upgrading.** Bounded by `credential.maxTtl` (default 24h). No CVE (pre-1.0, no external users known).

- **BYOK — master key as a first-class injection**: the library no longer reads `AGENTS_MASTER_KEY` from the environment. Master key flows through `injections.masterKey: MasterKey` as a required constructor argument. Consumers who source keys from KMS / Vault / Secrets Manager get a clean injection point; the library itself holds zero opinions about how key material is sourced. Env-var loading is now an opt-in convenience helper in the `@abaxxlabs/agents/bootstrap` subpath, used by `packages/server/`, the CLI, and the `npm create @abaxxlabs/agents` scaffold. ESLint rules (lib + server) statically prevent the env-read pattern from re-entering the library or being re-introduced via destructure / computed-key bypass. Closes the six-session library-shrinking arc: the core library holds no infrastructure opinions (no env reads, no stores, no transports fetched from environment).

### Breaking changes

- **`AgentScope.create(config, injections)` is now a two-parameter factory.** First parameter carries declarative material (`database`, `oidc`, `audit`, `credential`, `encryption.columns`, `log`, `scopeMode`). Second parameter carries pre-constructed and secret material (`masterKey`, `storage?`, `sdk?`, `pool?`, `serverIdentity?`). Both parameters are required because `injections.masterKey` is required.
- **`injections.masterKey: MasterKey` is required.** Removed from `AgentScopeConfig.encryption`. `AgentScopeConfig.encryption` becomes `{ algorithm?, columns? }` only.
- **`VcVerifierOptions.revocationStore` is required.** No silent fallback to `InMemoryRevocationStore` at the verifier layer. `AgentScope.create` supplies the default explicitly at the factory layer when `injections.storage` is omitted, so consumers who don't think about revocation get the same default they got before — but the verifier itself now refuses to be constructed without one.
- **`registerColumn()` re-registration on an already-registered column throws.** (Already shipped in v0.9.9.0; restated here because Session 6's BYOK protocol intersects with column-key persistence.) Use `rotateColumnKey` or `rewrapColumnKey`.
- **`MasterKeyMissingError` message changed.** New text points callers at `injections.masterKey` and `docs/migrations/byok.md`.

### Added

- `MasterKey` branded type — `Buffer & { readonly __brand: 'MasterKey' }`. Smart constructor `asMasterKey(buf: Buffer): MasterKey` validates 32-byte length and brands. Every crypto primitive (`wrapColumnKey`, `unwrapColumnKey`, `deriveSessionMacKey`, `loadColumnKeys`, `rewrapColumnKey`, `rotateColumnKey`, `verifyAllColumnKeys`) accepts `MasterKey`, not raw `Buffer`. Limits the surface area of functions that can accidentally receive master key material from an unaudited source.
- `MasterKeyMismatchError` — thrown by `loadColumnKeys` and `restoreAgents` when column keys decode but cannot be unwrapped under the supplied master key. Replaces the prior silent-fallback behavior where wrong-key boots degraded to `[ENCRYPTED]` placeholder reads. Wrong-key boots now fail loudly with a message that distinguishes "different master key" from "tampered data."
- `AgentScope.pruneRevocations(cutoff?: Date): Promise<number>` — public method for admin-side revocation expiration. The canonical replacement for the prior `scope.verifierInstance.revocationStore.pruneExpired(...)` reach-through.
- `VcVerifier.isRevoked(credentialId: string): Promise<boolean>` — public proxy over the (now-private) revocation store. External callers — including injection-wiring assertions in the test suite — use this instead of reading the private field. Pairs with the existing `revokeAsync(credentialId, opts)` method to form the complete public revocation surface on `VcVerifier`.
- `AgentScope.close()` zeros the master-key buffer in place. Best-effort given Node GC + V8 heap copies, but establishes hygiene at the primary storage location. Same treatment for derived keys held on the instance.
- `AgentScope` implements `[util.inspect.custom]` and `toJSON()` returning a redacted shape (`masterKey: '[REDACTED 32 bytes]'`, `sdk: '[SDK]'`, column keys elided). Default Node `console.log` / `JSON.stringify(scope)` / logger auto-serializers no longer leak key material.
- `composeStorageBackend(base, overrides)` helper in `src/storage/`. Mixed-backend escape hatch for "Postgres for 4 sub-stores, Redis for revocation" configurations. Does NOT chain `initialize()` across backends — caller responsibility, documented loudly.
- `@abaxxlabs/agents/bootstrap` subpath export. Two helpers:
  - `resolveMasterKeyFromEnv(): MasterKey` — reads `AGENTS_MASTER_KEY` and returns a branded `MasterKey`. Strict 64-hex-char validation; rejects whitespace, padding, base64, and any UTF-8 variant before decoding.
  - `parseMasterKeyHex(hex: string): MasterKey` — same strict parse for any non-env hex source (CLI flag, config field, KMS callback that returns hex). `resolveMasterKeyFromEnv` delegates to it.
- `verifyAllColumnKeys(pool, masterKey: MasterKey): Promise<{ ok: number, failed: Array<{ table, col, error }> }>` — read-only diagnostic for the `rewrapColumnKey` migration protocol (steps 3 + 5). Iterates `agent_keys` and reports per-row unwrap success/failure under the supplied master key. Does not throw on per-row failure; aggregates the full report. Schema-missing returns `{ ok: 0, failed: [] }` consistent with `loadColumnKeys`. Does not guess old-vs-new — the caller passes the specific key to test.
- `packages/server/` default-injects `PostgresRevocationStore` when `DATABASE_URL` is set. `REVOCATION_STORE` env var (`auto` | `memory` | `postgres` | `sqlite`, default `auto`) overrides. Single INFO log line on startup names the active store and durability claim.
- ESLint trust-boundary rules (D16, /) — currently `warn` severity, will promote to `error` after Lane D/E lands cleanly across consumers:
  - **Library core (`src/**/*.ts`, excluding `src/bootstrap/` and `src/cli/`)**: bans the bare string literal `'AGENTS_MASTER_KEY'` (Literal + TemplateLiteral, also covers `process.env['AGENTS_MASTER_KEY']` bracket access); bans broad `process.env.*` member access (dot + bracket notation), with an explicit justification-comment escape (`// eslint-disable-next-line no-restricted-syntax -- with-justification: <reason>`). Sanctioned env reads belong in `src/bootstrap/`.
  - **Server (`packages/server/src/**/*.ts`)**: bans the same literal patterns, plus `process.env.AGENTS_MASTER_KEY` member access specifically, plus the C1-review-driven destructure form (`const { AGENTS_MASTER_KEY } = process.env`). Other env reads (`DATABASE_URL`, `OIDC_*`, `SESSION_STORE`, `REVOCATION_STORE`) remain unrestricted — server is consumer-boundary code.
- JSDoc↔type CI workflow (`.github/workflows/jsdoc-types.yml` + `scripts/extract-jsdoc-examples.ts`). Walks `src/**/*.ts` AST, extracts \`\`\`ts blocks from `@example` annotations, type-checks the concatenation against the actual type surface. Structurally prevents the aspirational-JSDoc drift class that masked the Session 3 revocation gap for ~4 minor versions.

### Changed

- `loadColumnKeys` and `restoreAgents` now distinguish schema-missing (legitimate pre-migration case → empty map / no-op) from decrypt-failure (wrong master key → throws `MasterKeyMismatchError`). Schema-missing detection uses pattern-match on Postgres error codes, not catch-all swallows.
- `MasterKeyMissingError` message: "Master key not provided. Pass a 32-byte Buffer as `injections.masterKey` to `AgentScope.create(config, injections)`. For env-var bootstrap, import `parseMasterKeyHex` from `@abaxxlabs/agents/bootstrap` (strict 64-hex validation). See `docs/migrations/byok.md` for full examples."
- `packages/server/src/index.ts` reads `AGENTS_MASTER_KEY` exactly once at bootstrap via `resolveMasterKeyFromEnv()`; the resulting `Buffer` is threaded to all consumers (`AgentScope.create(config, { masterKey })` AND `deriveSessionMacKey(masterKey)`). Removed: control-channel env writes, second env reads, and the format-sniffing `hex/utf8` branch.
- `demo/showcase/src/server.ts` migrated off env-var control-channel. The 6 prior `process.env.AGENTS_MASTER_KEY = ...` writes are replaced with explicit `Buffer` arguments to each `AgentScope.create` call. Per-session and per-org key switching happens via `injections.masterKey` rather than env mutation.
- `packages/create-agents/template/src/index.ts` (the `npm create @abaxxlabs/agents` scaffold) reads env once at bootstrap and passes `Buffer` into `AgentScope.create` — no env writes. Day-1 consumers learn the correct pattern.
- CLI tools (`src/cli/init.ts`, `src/cli/encrypt.ts`, `src/cli/demo.ts`, `src/cli/index.ts`) pass `Buffer` explicitly. CLI commands may read env at their own boundary but never write env for the library to re-read. `--master-key` flag inputs flow through `parseMasterKeyHex` for strict validation.

### Library / SDK boundary

- The library no longer reads `AGENTS_MASTER_KEY` from the environment. Every active `AGENTS_MASTER_KEY` site is in consumer-boundary code (`@abaxxlabs/agents/bootstrap`, `packages/server/`, `src/cli/`, demos, scaffolds) — the lint rule enforces this structurally. (Other library env reads — `NODE_ENV` for dev defaults, `AGENTS_TRUSTED_SERVERS`, `AGENTS_CONSUMER_DOMAINS`, etc. — are unaffected by this release; they remain pending broader review under D16.)
- `StorageBackend.sessions` retained. Removing it would introduce a second breaking change for marginal symmetry; Session 5's contract stays intact.
- `AgentScope.verifierInstance` getter retained (testing-ergonomics tradeoff). The `revocationStore` field on the verifier is now fully `private`; the new public `VcVerifier.isRevoked()` proxy is the sanctioned read path. `AgentScope.pruneRevocations()` is the sanctioned admin path. Full deletion of the `verifierInstance` getter is deferred until a concrete friction point surfaces.

### Upgrade path

- See `docs/migrations/byok.md` for the full migration guide: 5-question decision tree, environment audit checklist, four worked examples (env-only/same-key, env-only/new-key, config-hex/same-key, new-key-with-rewrap), and the `rewrapColumnKey` migration protocol.
- **Diagnostic CLI** (`agents migrate-check`, also available via `npx @abaxxlabs/agents migrate-check`): read-only scanner. Walks the CWD, detects `process.env.AGENTS_MASTER_KEY` reads/writes, `encryption.masterKey` references, and `AgentScope.create(` call sites. Categorizes the project into one of the four migration cases (or the trap state where env was silently winning) and points at the relevant doc section. Useful for triaging codebases with many consumer projects. Read-only by design — no edits, no telemetry, no network calls.
- **MAC-key co-rotation note**: BYOK key change requires a server restart (or explicit MAC-key re-derivation) for session-envelope coherency. Documented in the migration guide as a planned user-visible side effect.
- **Rollback procedure**: `docs/migrations/v0.9.10-rollback.md`. No DB schema rollback (Session 6 ships zero new migrations). Code + bootstrap revert only. Data-loss risk only if the master key was rotated during the v0.9.10.0 upgrade window (the rollback doc explains both rotate-back and keep-new-key options).
- **Support runbook**: `docs/internal/support-runbook-v0.9.10.0.md`. Operational diagnostics for what's new in v0.9.10.0 — revocation-enforcement post-upgrade verification (which store am I actually running?), wrong-key boot triage (`MasterKeyMismatchError` decision tree), and admin operations (mass revoke, manual prune, audit queries). The pre-existing session-3 / session-5 runbooks remain authoritative for ongoing Postgres revocation-store and session-store CRUD operations.

### Dependencies

- No new runtime dependencies.

### Not breaking

- The library remains importable in any runtime. The library no longer reads env vars, so deployments that bundled the library into a non-Node runtime (workers, edge) continue to work — the env-var path is consumer-side.
- v0.9.9.0's `rotateColumnKey` / `rewrapColumnKey` primitives are unchanged.
- Single-instance `SESSION_STORE=memory` deployments behave identically.

## [0.9.9.0] — 2026-04-24

### Security posture

- ****: Column-key rotation is now a first-class, correct primitive. Before this release, the only way to change a column's key material was to re-call `registerColumn()`, whose `ON CONFLICT DO UPDATE` silently overwrote the wrapped key and left all existing row ciphertext permanently unreadable — a silent data-loss footgun flagged during the hackathon review. Rotation now decrypts every row under the old key, re-encrypts under a new key, and swaps the wrapped key atomically in a single transaction. Failure at any step rolls back cleanly; the column is never in a partially-migrated state. Every rotation emits an `agent_audit` entry inside the transaction — the record answering "who rotated what when" exists if and only if the rotation committed. The footgun in `registerColumn()` is now closed: re-registration throws a clear error pointing callers to the rotation primitives.

### Added

- `rotateColumnKey({ pool, agentDid, tableName, columnName, masterKey })` — decrypts all rows with the old column key, generates a new column key, re-encrypts every row under it, updates the wrapped key in `agent_keys`, and appends an audit entry — all in one transaction. Row updates happen BEFORE the wrapped-key swap, so a mid-pass failure leaves the column entirely on the old key (readable). `SELECT ... FOR UPDATE` on the `agent_keys` row serializes concurrent rotations of the same column without reaching across the boundary to lock consumer data tables.
- `rewrapColumnKey({ pool, agentDid, tableName, columnName, oldMasterKey, newMasterKey })` — re-wraps the existing column key under a new master key. Column key and row ciphertext are unchanged; only the wrapped form in `agent_keys.encrypted_key` is rewritten. Shipped alongside rotation so Session 6 (BYOK) inherits the primitive instead of introducing new crypto surface.
- `KeyRotationFailedError` with `phase` tag (`unwrap-old-key` | `decrypt-row` | `encrypt-row` | `wrap-new-key` | `update-agent-keys` | `audit-append`). Underlying cause preserved as `cause`. Operators can distinguish wrong-master-key from pre-existing row corruption without reading stack traces.
- `KeyRotationPhase` public type export.
- **21 new tests** — rotation happy path (multi-row, empty table), mid-rotation rollback semantics, wrong master key, repeated rotation, rewrap happy path, rewrap wrong old master key, audit entry emission for both primitives, `registerColumn` re-registration throws, `registerColumn` first registration succeeds, concurrent-rotation serialization via mocked `FOR UPDATE`.

### Changed

- `registerColumn()` ON CONFLICT path: `DO UPDATE SET encrypted_key = $3, rotated_at = NOW()` → `DO NOTHING`. When the 0-row RETURNING signals existing registration, the function throws with a message pointing to `rotateColumnKey` / `rewrapColumnKey`. The old path had no legitimate caller — `encryptColumnInPlace` is protected by its own bytea guard, and silently destroying ciphertext on re-registration was a latent data-loss bug.

### Library / SDK boundary

- **No LOCK TABLE.** A prior draft proposed holding a table-level lock inside the rotation transaction. Rejected by eng-review F-1: the library does not hold infrastructure opinions on consumer write paths. Write-quiescence is a caller-owned policy (maintenance flag, read-only mode, external advisory lock, queue pause). The JSDoc on both primitives documents the invariant explicitly; any future maintainer reaching for `LOCK TABLE` must re-read F-1 first.
- **No streaming read.** Per-row SELECT → decrypt → re-encrypt → UPDATE is O(rows) round-trips (~15–25s for 10,000 rows on local Postgres). Batched multi-row UPDATE is an optional future optimization for consumers with hot paths over millions of encrypted rows; not shipped preemptively.
- **No embedded authz.** The primitives take `agentDid` for audit attribution only. Who is authorized to rotate is a consumer concern; the library stays out.
- Session 6 (BYOK, v0.9.10.0) now needs no new crypto primitive — it threads the existing `masterKey` parameter into the rewrap entry point.

### Dependencies

- No new dependencies. `uuid@^10.0.0` already present.

### Not breaking

- Existing callers of `rotateColumnKey` / `rewrapColumnKey`: none — both are new entry points.
- Existing `encrypt` / `decrypt` / `registerColumn` callers: unchanged, EXCEPT that re-calling `registerColumn` on an already-registered column now throws instead of silently destroying ciphertext. This is the intended correction; any caller relying on the old behavior was destroying data.

## [0.9.8.0] — 2026-04-24

### Security posture

- ****: Session state no longer pinned to a single server process. Before this release, a user who authenticated against instance A and hit instance B on their next request was rejected because the session map was process-local. Session envelopes are now persisted via `ISessionStore`; on cross-instance hit, the target instance re-establishes a live `AuthenticatedSession` from the envelope + its local keystore + OIDC claims. **No raw private key material is persisted.** HMAC-SHA256 protects envelope integrity (HKDF-derived key from master key). Scope ceiling and parent credentials are re-derived / re-verified on every re-establishment; envelope bytes are never trusted as authority. Paid-tier sessions that require an OAuth access token fall back to silent re-auth on cross-instance hit (no token persistence in v0.9.8.0).

### Added

- `ISessionStore` — fifth sub-store under `StorageBackend` (alongside `IAgentStore`, `IAuditStore`, `IContextStore`, `IRevocationStore`). Interface in `src/storage/types.ts`. Adapters: `PostgresSessionStore` (durable, multi-instance, 10s read-through cache), `SqliteSessionStore` (file-backed, Chief/local, WAL mode), `InMemorySessionStore` (zero-config default, single-instance).
- `SessionEnvelope` type — re-establishment metadata (DID, OIDC claims, compact parent JWT, lifecycle fields). Explicitly omits `humanPrivateKey`, `parentAccessToken`, refresh tokens, and derived column keys.
- Migration 008 — `sessions` table with `mac BYTEA`, `expires_at TIMESTAMPTZ NOT NULL`, `human_did` denormalized for GDPR Article 17 deletes. Idempotent (`IF NOT EXISTS`).
- `envelope-mac` primitive — HMAC-SHA256 over RFC 8785 (JCS) canonical JSON encoding of the envelope. HKDF-derived key from library master key. Exported context strings (`HKDF_CONTEXT_SESSION_MAC`) so Session 6 (BYOK) reuses the pattern without reverse-engineering constants (RY-7).
- `MAX_ENVELOPE_BYTES = 32768` (32KB) size cap measured on canonical-encoded output (RY-6). Defense against unbounded `oidcGroupClaims` from self-hosted Keycloak tenants.
- `pruneExpired(beforeTs?, limit?)` on `ISessionStore` — consumer-scheduled; library does not run a background loop.
- `deleteByHumanDid(did)` on `ISessionStore` — GDPR Article 17 one-liner. `human_did` indexed in migration 008.
- `DELETE /admin/sessions/:token` endpoint — admin API key auth (fail-closed when unset); emits `session.revoked` audit.
- Structured session audit vocabulary (JSON-line, grep `[audit] session.*`): `session.rehydrated`, `session.rehydrate_rejected_integrity`, `session.rehydrate_rejected_provider`, `session.rehydrate_rejected_other`, `session.revoked`. Raw tokens NEVER logged (only SHA-256 hashes).
- `SESSION_STORE` env var: `memory` (default), `postgres`, `sqlite`.
- `SESSION_STORE_MODE=dual` opt-in for zero-re-auth rolling upgrades (D17).
- `OIDC_ALLOWED_ISSUERS` env var — fail-closed default (D19). Multi-instance deployments MUST configure.
- `ADMIN_API_KEY` env var — required to enable `DELETE /admin/sessions/:token`.
- `PostgresSessionStore` 10s per-instance read-through cache (D15) with enforced invariants: cache TTL = min(configured, envelope.expiresAt − now); evicts on `put()` and `delete()`; never authoritative on deletion; never short-circuits MAC verification.
- Per-instance singleflight coalescer (D13) on `get()`: concurrent calls for the same token join one in-flight promise.
- Release artifacts: support runbook, migration 008 rollback doc, data retention policy (GDPR Article 5(1)(e) / Article 17), upgrade-path doc (5th artifact — Session 5 replaces an existing mechanism).
- **69 new tests** — envelope-mac unit (19), in-memory adapter (13), SQLite adapter (9), Postgres adapter live-DB (9), cross-backend contract parity (16), library-factories-stateless regression guard (3).

### Changed

- `packages/server/src/index.ts` no longer holds a process-local `Map<token, SessionEntry>`. Session lifecycle goes through the injected `ISessionStore`. A small per-instance `liveSessions` cache still holds the non-serializable `AuthenticatedSession` closure for hot-path lookups, but it is not authoritative — misses fall through to durable store + rehydrate.
- `requireSession` middleware is now async to support cross-instance rehydrate. Mapping: `EnvelopeIntegrityError` → 401 `SESSION_INTEGRITY_FAILED`, `ProviderNotAllowedError` → 401 `PROVIDER_NOT_ALLOWED`, other store errors → 503 `SESSION_STORE_UNAVAILABLE` (D14, no silent fallback).
- SQLite migrations add `PRAGMA synchronous = NORMAL` alongside existing `PRAGMA journal_mode = WAL` (NF-7). Retroactively applied to all SQLite adapters under `StorageBackend`.

### Library / SDK boundary

- Session storage is a public, stable contract in core + three shipped adapters. Non-default adapters (Redis, DynamoDB, sticky-sessions-with-local-cache) are consumer territory — the interface accepts them.
- Library `src/auth/` factories confirmed stateless (Task 3 verification test). Session 6 inherits this.
- HKDF context-string pattern established for master-key derivation. Session 6 reuses via `HKDF_CONTEXT_SESSION_MAC` as the precedent constant.

### Dependencies

- **New:** `canonicalize@2.1.0` (exact pin, no caret). RFC 8785 JCS implementation for deterministic envelope encoding. Pinned exactly because a silent version bump that changes number formatting or escape rules invalidates every envelope in flight. Vendor-contingency path documented in runbook (~30 LOC if maintainer goes dark).

### Not breaking

- Single-instance deployments (`SESSION_STORE=memory`, default): behavior is identical to v0.9.7.x / v0.9.6.x.
- Consumers who ignore `ISessionStore` and don't set `SESSION_STORE`: no change.
- Library `src/auth/` factories: unchanged.

### Deferred to v0.9.8.1+

- **Parent-IdP re-verification on rehydrate (D11 / RY-4 / RY-5):** in v0.9.8.0 we do not persist or re-verify the compact parent JWT during re-establishment. The envelope type reserves a `parentJwt` field for this purpose; if a session's `issueCredential` call needs a live parent access token, it falls back to re-auth-on-miss per D5. If the parent-cred re-verify path is wired in a future release, RY-4 (error body doesn't leak parent topology) and RY-5 (30s closed-state circuit breaker) must land alongside it.

## [0.9.6.0] — 2026-04-23

### Security posture

- ****: Credential revocations now survive process restart and are coherent across instances (default 30-second cross-instance staleness bound). Previously, revocations were process-local — they disappeared on restart and were invisible to other instances. This was a security-posture gap flagged during the Session 3 review. A revocation performed on instance A is visible on instance B within `pollIntervalMs` (default 30s).

### Added

- `IRevocationStore` — fourth sub-store under `StorageBackend` (alongside `IAgentStore`, `IAuditStore`, `IContextStore`). Interface in `src/storage/types.ts`. Adapters: `PostgresRevocationStore` (durable, cross-instance coherent), `SqliteRevocationStore` (file-backed, Chief/local), `InMemoryRevocationStore` (zero-config default).
- `InMemoryRevocationStore` — process-local default for zero-config backward compatibility. Exported from the public API for consumers who want to inject their own instance.
- `PostgresRevocationStore` in `src/storage/postgres/revocation-store.ts` — configurable poll coherency (default 30s), LISTEN/NOTIFY opt-in documented.
- `SqliteRevocationStore` in `src/storage/sqlite/revocation-store.ts` — BEGIN IMMEDIATE for write serialization (D7 pattern from).
- Migration 007 — `revoked_credentials` table with `expires_at TIMESTAMPTZ` + partial index. Idempotent (IF NOT EXISTS).
- `VcVerifier.revokeAsync()` — D5-compliant async revocation that throws on storage failure. Call sites in `src/auth/agent.ts` use this instead of the deprecated `revokeLocally()`.
- Background pruning — 24h `pruneExpired()` job in the server package deletes revocations whose underlying credential expired >30 days ago.
- Row-level locking on `isRevoked()` reads — mirrors audit-chain pattern.
- HTTP authz: `DELETE /credentials/:id` now verifies caller session matches credential issuer DID (default deny). Previously any authenticated session could revoke any credential.
- Release artifacts: support runbook, migration 007 rollback doc, data retention policy (GDPR Article 5(1)(e) / SOC 2 CC7.1).
- **26 new tests** — InMemoryRevocationStore unit (11), SqliteRevocationStore integration (2), D10 regression (3 from parent-credential.test.ts + 3 new), D7 race sequencing (2), migration 007 format (2), VcVerifier integration (3).

### Changed

- `revokeCredential()` in `AuthenticatedSession` now returns `Promise<{ sdkNotificationFailed?: Error }>` instead of `Promise<void>`. Local `IRevocationStore` write is the canonical revocation authority. SDK call (`sdk.vc.revokeCredential`) is a best-effort outbound notification — SDK failure does NOT fail the call; it is surfaced in `sdkNotificationFailed`.
- Revocation authority model: local store is canonical (D6). SDK call is notification only.

### Breaking

- `revokeCredential()` is now async and throws on storage failure. Callers that previously relied on best-effort `revokeLocally()` semantics must handle rejection as a hard failure.
- The return type changed from `Promise<void>` to `Promise<{ sdkNotificationFailed?: Error }>`. Callers that ignore the return value (common: `await session.revokeCredential(id)`) are unaffected.

## [0.9.5.0] — 2026-04-23

### Fixed

- ****: serialized audit chain-head read prevents hash chain fork under concurrent init. `IAuditStore` now exposes `loadLastRecordLocked()` — Postgres uses `pg_advisory_xact_lock(1234567890)` inside a transaction; SQLite uses `BEGIN IMMEDIATE` (better-sqlite3 `.immediate()`) to acquire a RESERVED lock before the SELECT executes. `AuditLogger.initialize()` calls `loadLastRecordLocked()` instead of `loadLastRecord()`, preventing two processes from reading the same chain-head and forking the hash chain on concurrent startup.
- ****: `verifyAuditChain` now uses `crypto.timingSafeEqual` for hash comparison via a `hashesEqual()` helper that length-checks first (mismatched lengths → false, no `timingSafeEqual` call). Closes the timing channel leak when the endpoint is invoked over an authenticated HTTP session.

### Added

- ****: `GET /credentials?agentDid=&issuedAfter=` endpoint in the server product. Returns credential records (credentialId, agentDid, ownerDid, issuedAt) derived from the audit trail for the authenticated caller's agents. Both query params are optional; they compose with AND semantics. Unauthenticated requests return 401. OpenAPI spec updated.
- **29 new unit tests** — (SQLite + Postgres-style mock: loadLastRecordLocked serializes init read, initialize() calls locked variant), (mismatch at byte 0, last byte, middle byte, non-hex hash — all detected), (unauthenticated 401, authenticated list, agentDid filter, issuedAfter filter, both params AND, invalid issuedAfter 400, empty result is [] not 403).

## [0.9.4.0] — 2026-04-23

### Fixed

- ****: `scopeMode='encryption-only'` now throws on `ScopeEngine` construction unless `AGENTS_ALLOW_LEGACY_SCOPE_MODE=true` is set in the environment. Prevents silent opt-in to a weaker security posture. Existing tests that exercise this mode set the env var in `beforeAll`/`afterAll` blocks.
- ****: `timeOfDayRule` validates caller-supplied `context.timezone` against `Intl.supportedValuesOf('timeZone')` before use. Invalid strings throw the new `InvalidTimezoneError`. The supported timezone set is memoised — one allocation per process lifetime. UTC and GMT are handled via an explicit alias set (omitted from `supportedValuesOf` in some ICU versions but accepted by `Intl.DateTimeFormat`).
- ****: `issueCredentialFromParent` accepts optional `{ ceiling?, context? }` as a fifth parameter. When `ceiling` is supplied, `assertScopeFitsInCeiling` is called before the provider is contacted — the provider is never called if the ceiling rejects. Fully backwards-compatible: existing callers that omit the parameter see no behaviour change.
- ****: `createMockSession` throws unless `NODE_ENV` is `'development'` or `'test'`. Unset `NODE_ENV` is treated as production. The guard lives inside the function (not in a caller wrapper) to prevent bypass by direct SDK consumers.

### Added

- **18 new unit tests** — (3 cases: throw without env, pass with env, projection unaffected), (7 cases: valid IANA, UTC, invalid string, EST5EDT abbreviation, empty string, undefined, memoisation), (4 cases: no opts, ceiling accepts, ceiling rejects + provider not called, ceiling without context), (4 cases: test, development, production, unset — each with env restore).

## [0.9.3.0] — 2026-04-23

### Added

- **Time-of-day issuance policy** — `timeOfDayRule(blockFromHour, timezone?)` lets
  you attach temporal rules to a `ScopeCeiling`. Credential issuance is blocked at
  or after the configured hour. Timezone is ceiling-authoritative: caller-supplied
  context timezones cannot override the ceiling's configured zone.
  `PolicyViolationError` is thrown on violation and `IssuanceContext` carries
  the requestedAt timestamp and optional IANA timezone.

- **Audit chain verification** — `AuditLogger.verifyAuditChain()` walks the
  hash-linked audit log and returns `{ ok, totalRecords }` or `{ ok: false, failedAt }`.
  Useful for compliance checks and tamper detection without re-verifying Ed25519
  signatures on every record.

- **28 new unit tests** — full coverage for `timeOfDayRule`, `PolicyViolationError`,
  `assertScopeFitsInCeiling` with rules, `verifyAuditChain`, `loadColumnKeys`
  resilience on bad keys, and `generateDidKeyFromSeed` determinism.

### Fixed

- **Showcase demo stability** — resolved all 11 findings from Anto's hackathon
  dry-run: scoped queries per-agent credentials, Beat 5/7 audit schema and chain
  integrity, column decryption error handling, mock auth DID stability (now
  deterministic from human name seed), DB isolation, return-to-Beat-1 on reset.

- **SDK error messages** — `DecryptionFailedError` now says "encrypted with a
  different key" instead of "wrong key or tampered data", making master-key mismatch
  diagnosable without guessing. `loadColumnKeys` warns and skips columns wrapped with
  a prior master key rather than crashing startup.

- **Migration runner** — `initStorage()` now surfaces SQL errors from failed
  migrations instead of swallowing them silently. Half-applied migrations fail loudly.

- **Credential API response** — `POST /credentials` now returns `jti` and `exp`
  in the response body so callers can track credential lifecycle without decoding
  the JWT themselves.

- **run.sh hardening** — Docker preflight, nested `npm install`, guarded `open`
  calls, and OpenClaw sandbox resilience for the hackathon demo script.

### Changed

- **Rebrand** — Swagger UI title and sandbox name updated to Agents++.
  `packages/server` package name updated to `@abaxxlabs/agents-server`.

## [0.9.2.0] — 2026-04-19

### Added

- **AbaxxOne parent instance credentials** — agents can now receive credentials
  issued by an organization's DID instead of the human's self-issued DID. Any
  verifier that trusts the org can verify the agent without contacting the issuing
  human. `requestAgentCredential()` on `AbaxxOneOidcProvider` handles the full
  exchange, with automatic fallback to free-tier local signing when the parent
  instance is unavailable.

- **Parent trust anchors** — `addParentTrust(parentDid)` on `LocalTrustAnchorStore`
  registers org DIDs with source `'parent'`. Parent anchors are ephemeral by
  design: re-derived from the credential chain each session, never persisted to
  keystore. Persistent anchors (source `'env'` or `'api'`) cannot be overwritten
  by a parent anchor, preventing trust downgrade.

- **Parent scope ceiling enforcement** — AgentVerifier Step 2.5 checks that agent
  capabilities fit within the parent's grant via `CapabilityEngine.isSubsetOf()`.
  Throws `ParentScopeExceededError` with the excess capabilities when the agent
  requests more than the parent authorized.

- **V3 audit records with orgId** — when an agent operates under an AbaxxOne parent
  instance, audit records include `orgId` for per-organization compliance reporting.
  Version auto-selected: V3 when orgId is present, V2 otherwise. `org_id` column
  added to both Postgres and SQLite audit stores with index for filtered queries.

- **Story-07 demo** — 8-step zero-dependency demo covering the full paid-tier
  lifecycle: org-issued credentials, parent trust anchors, V3 audit, scope ceiling
  enforcement, and graceful fallback when the parent instance is unavailable.

- **21 new tests** — `test/parent-credential.test.ts` covers all 5 parent credential
  paths: trust anchor management, credential delegation, session fallback,
  capability subset logic, verifier ceiling check, and V3 audit record format.

### Fixed

- **Bare catch in credential fallback** — `createSessionFromDid` now catches only
  `ParentCredentialRequestFailedError` instead of swallowing all errors. Non-parent
  failures (network, auth, serialization) propagate correctly.

- **Capability ceiling bypass** — removed redundant `capabilities.length > 0` guard
  in AgentVerifier Step 2.5 that allowed agents with empty capability sets to skip
  the ceiling check entirely. `isSubsetOf()` handles empty sets correctly (vacuous
  truth).

- **orgId truthiness check** — `signAuditRecord` now uses `record.orgId !== undefined`
  instead of `if (record.orgId)`, preserving empty-string orgId values through the
  hash chain.

## [0.9.1.1] — 2026-04-18

### Changed

- **Capital markets demo scenario** — all 6 user stories and helpers rewritten
  from healthcare (patients, dob, diagnosis) to capital markets (order_book, ticker,
  quantity, price, client_id, strategy, model_version). Two humans (James Park,
  Maria Torres), three agents (Trading Executor, Compliance Monitor, Regulatory
  Reporter). IMF TNM/2025/16 and MAS regulatory framing throughout.
- Order book fixture expanded from 3 rows to 6 rows, 3 encrypted columns to 5
  encrypted columns — richer demo surface for scope isolation and audit stories.

### Fixed

- No-op ternary in helpers.ts row 2 (copy-paste artifact from column key migration).

## [0.9.1.0] — 2026-04-18

### Added

- **Projection scope mode** — new `scopeMode: 'projection'` (now the default)
  rejects queries referencing ANY column not in the credential's scope, not just
  encrypted ones. The previous behavior is preserved as `scopeMode: 'encryption-only'`
  for migration from pre-projection codebases. Projection mode closes boolean oracle
  attacks where agents infer values through unencrypted WHERE/ORDER BY/HAVING clauses.

- **Paid-tier capability boundary** — `CapabilityRequiresPaidTierError` provides
  actionable error messages with capability name, namespace, and AbaxxOne signup URL
  when an agent invokes a capability that requires a paid subscription. Free-tier
  capabilities (mcp:\*, agents:\*, did:resolve, vc:verify, vc:present, scope:read,
  trust:list) are unaffected.

- **Six runnable user stories** in `demo/user-stories/` — zero-dependency demos
  that exercise the SDK end-to-end: two-peer credential flow, column-level scope
  enforcement, tamper-evident audit trails, credential revocation, SQL read-only
  guard, and sandboxed free-tier operation. Each runs with `npx tsx` and includes
  expected output for verification.

### Fixed

- **ScopeMode type safety** — `ScopeMode` is now defined once in `scope-engine.ts`
  and imported everywhere, preventing drift between type definitions. Constructor
  validates the value at runtime, rejecting invalid strings that would silently
  fall through to encryption-only behavior.

- **Table-qualified column extraction** — `SELECT patients.name` no longer causes
  false-positive `ScopeViolationError`. The SQL parser was extracting all String
  fields from ColumnRef AST nodes (table qualifier + column name), then re-qualifying
  each with the declared table, producing `patients.patients` which never matches
  any scope entry. Fixed to extract only the last field (the actual column name).

- **MCP paid-tier error details preserved** — `CapabilityRequiresPaidTierError` now
  has a dedicated handler in the MCP error mapper, preventing it from falling through
  to the generic `AgentScopeError` catch which strips `details`. Agents now receive
  the `signupUrl`, `capability`, and `namespace` fields needed for actionable upgrade
  prompts.

## [0.9.0] — 2026-04-18

### Added

- **Identity migration pipeline** — when a user upgrades from did:key (free tier)
  to did:dht (AbaxxOne), their DID changes. This release adds the full migration
  flow: detect an IdentityMigrationCredential in a VP, execute an atomic ownership
  transfer (SERIALIZABLE transaction), and maintain a grace period where both DIDs
  are accepted. Seven of the eight planned steps (AS-1 through AS-6, AS-8) are
  implemented; AS-7 (credential re-issuance) is deferred.

- **DID alias registry** — bidirectional in-memory registry for alias-aware DID
  comparison during the grace period. Three scope engine equality checks
  (C1 owner, delegation chain, issuer consistency) now use alias-aware matching
  instead of strict `===`.

- **Migration credential detection in VPs** — the VC verifier scans VP inner VCs
  for `IdentityMigrationCredential` type before processing scope VCs. Returns a
  new `MIGRATION_DETECTED` status with extracted claims (previousDid, oidcSubject,
  migrationMethod, oidcIssuer, migratedAt).

- **Alias-aware audit trail** — audit log export automatically expands a single
  agentDid filter to include all equivalent DIDs from the alias registry. Both
  Postgres (`ANY()`) and SQLite (`IN()`) stores support multi-DID queries.

- **Postgres migration 004** — `agent_did_aliases` table with unique
  credential_hash index and new_did index for reverse lookups.

## [0.8.0] — 2026-04-18

### Added

- **REST API parity** — three new endpoints close the gap between REST and MCP
  surfaces. `GET /agents` lists agents owned by the authenticated human (with
  owner/limit query params). `POST /audit/verify` checks an audit record's
  Ed25519 signature. `POST /audit/verify-chain` walks the hash chain from
  GENESIS and reports broken links, proving no records were tampered with.

- **MCP delegate-credential tool** — the 13th MCP tool. A supervisor agent can
  delegate a subset of its credential to a worker agent. Two-axis enforcement:
  subset against source credential AND session scope ceiling.

- **Verifiable Presentations (VP)** — W3C-compliant VP support in the verifier
  and scope engine. VCs are now reusable credentials (like a driver's license);
  replay protection tracks at the VP layer (like showing it at a checkpoint).
  `createPresentation()` wraps a VC JWT in a signed VP with fresh nonce, optional
  audience binding, and 5-minute expiry. The scope engine auto-wraps raw VCs in
  VPs when the agent has a signer available.

- **VP audience binding** — `expectedAudience` option in `VerifyOptions` prevents
  VP replay across servers. A VP captured from Server X cannot be presented to
  Server Y. New `WRONG_AUDIENCE` status in `VerificationResult`.

- **Hackathon one-command bring-up** (`demo/hackathon/run.sh`) — single script
  starts Postgres, seeds data, launches Keycloak OIDC, login page, showcase demo,
  OpenClaw sandbox with port forwarding, and the REST server. Test users:
  analyst/analyst (scoped) and admin/admin (full access).

- **OpenClaw agent skill** (`demo/hackathon/SKILL-openclaw.md`) — teaches a
  sandboxed AI agent to use the agents REST API via curl. Covers session
  creation, credential issuance, scoped queries, and delegation using the
  Park/Torres capital markets personas.

- **OIDC login page** (`demo/nemoclaw-login/index.ts`) — browser-based Keycloak
  sign-in with PKCE flow. Exchanges authorization code directly with Keycloak
  for raw id_token, sends it as Bearer to the REST server for verified session
  creation, and shows session details (DID, scope ceiling, curl examples).
  Falls back gracefully if REST server is unreachable.

- **Park/Torres Keycloak users** — JamesPark (Head of Trading, all 7 order_book
  columns) and MariaTorres (CCO, 5 columns: ticker/side/quantity/price/model_version)
  added to the Keycloak realm with CamelCase login credentials.

- **Sandbox network policy** (`demo/nemoclaw/sandbox-policy.yaml`) — L7 HTTP
  proxy rules for Venice AI inference API access and agents REST API ports.

- **Hackathon cheatsheet** (`demo/hackathon/CHEATSHEET.md`) — port map, test
  users, directory reference, and quick commands.

### Changed

- **REST server auth restructure** — Bearer token verification now works in all
  modes (dev + production). Previously gated behind `else DEV_AUTH_ENABLED`,
  making it structurally unreachable in development. Bearer header is checked
  first, mock DIDs fall back in dev mode. Removed unverified `oidcIdentity`
  body-claims path (trust boundary fix).

- **Showcase demo** updated to capital markets scenario (order_book data).
  BeatScope component expanded with multi-column visualization. Fixture serving
  and CORS support added to showcase server.

- **MCP HTTP transport** binds to `0.0.0.0` instead of loopback for sandbox
  accessibility. Required for OpenClaw sandbox proxy to reach the host.

### Fixed

- **Nonce bypass via empty string** — `createPresentation()` used nullish
  coalescing (`??`) for nonce, which passed empty string through. The verifier
  treats empty string as falsy, disabling replay protection. Changed to `||`.

- **XSS in OIDC login page** — six OIDC identity fields and `error_description`
  were interpolated directly into HTML. Added `escapeHtml()` utility and
  `text/plain` content type for error responses.

- **Predictable /tmp path** — OIDC identity file used `/tmp/oidc-identity.json`.
  Changed to `mkdtempSync()` for unique temp directory per invocation.

- **Silent background failures** — login page and showcase demo stdout/stderr
  went to `/dev/null`. Redirected to log files for debugging.

- **`WRONG_AUDIENCE` type union** — status value was missing from the
  `VerificationResult` union type, requiring `as any` casts. Added to union,
  removed all casts (VP path and raw VC audience check).

- **Phase 2 identity endpoints** — four new REST endpoints complete the server
  identity surface. `GET /whoami` returns the server's DID and method.
  `POST /sign` signs payloads with Ed25519 (domain-separated, rate-limited
  100/min). `GET /discover` returns trust topology (DID, method, anchors).
  `POST /challenge` issues time-bound HMAC-signed VP challenges (rate-limited
  30/min). All four also added to the MCP REST bridge stub.

- **OpenAPI spec** expanded to 14 endpoints with full request/response schemas,
  `Identity` tag group, and auth header documentation for audit endpoints.

### Security

- **MCP SSE multi-tenant transport** — replaced single-variable SSE transport
  with a `Map<string, SSEServerTransport>` keyed by SDK session ID. Prior
  design allowed a second connection to hijack the first client's transport.

- **MCP SSE authentication** — every SSE connection now requires `x-session`
  query param (EventSource can't set custom headers). Each connection gets
  its own MCP server instance bound to the authenticated session's identity
  and scope ceiling.

- **Auth on sensitive endpoints** — added `requireSession` middleware to
  `POST /sign`, `POST /challenge`, `GET /audit`, `POST /audit/verify`, and
  `POST /audit/verify-chain`. Previously these were unauthenticated.

- **Provider dispatch hostname match** — replaced `issuer.includes('google')`
  substring matching with `new URL(iss).hostname` exact match. Prevents
  provider confusion attacks via crafted issuer URLs.

- **Challenge rate limiter** — 30 requests/min per session with 60-second
  window reset. Prevents challenge flooding.

- **MCP_ENABLED env var** — new toggle for enabling MCP without requiring
  mock identity. Backward compatible with existing MCP_MOCK_HUMAN.

- **CORS origin allowlist** — replaced permissive `cors()` with an explicit
  allowlist of `localhost:3001`, `3100`, `3200` (and `127.0.0.1` equivalents).
  Configurable via `CORS_ORIGINS` env var for production deployments.

- **Session TTL with sweep** — in-memory sessions now expire after 4 hours
  (configurable via `SESSION_TTL_MS`). A background sweep runs every 5 minutes
  to evict expired entries, preventing unbounded memory growth from leaked
  tokens. `getSession()` also lazily evicts on read.

- **Per-session rate limiting** — rate limit buckets are keyed by
  `sessionToken:endpoint`, isolating abuse to a single session. Prevents one
  compromised session from exhausting global rate limits. Stale buckets swept
  every 5 minutes.

- **MCP POST /mcp/messages auth** — the JSON-RPC endpoint now requires
  `x-session` header AND validates that the session token matches the one used
  to establish the SSE transport (`mcpTransportAuth` binding). Prevents
  sessionId guessing attacks.

- **Explicit JSON body limit** — `express.json({ limit: '100kb' })` makes the
  body size limit visible rather than relying on Express's implicit default.

- **fetchUserInfo failure logging** — OIDC userinfo fetch failures are now
  logged with `console.warn` instead of being silently swallowed.

- Review decisions documented in `demo/hackathon/REVIEW-DECISIONS.md` covering
  all 14 findings from testing, security, and adversarial review passes.

- **Delegation chain verification** — `delegateCredential()` is now async with
  source credential verification. DWN-aligned delegation chain with
  `grantedBy`/`grantedTo`/`delegatedGrantId` fields. C1 owner check walks the
  chain to verify human-owner-to-delegator-to-credential trust path.

- **Tenant-isolated audit endpoints** — audit REST endpoints (`GET /audit`,
  `POST /audit/verify`, `POST /audit/verify-chain`) now filter by the
  authenticated session's `humanDid`, preventing cross-tenant audit record access.

- **Three adversarial findings closed** — provider confusion hostname check
  tightened, session sweep interval hardened, credential delegation gaps
  documented and addressed.

- **Venice API key notice** — internal-only documentation strengthened for the
  Venice AI inference API key used in sandbox environments.

- **VP replay cache bounded** — `VcVerifier.seenJtis` Map now enforces a
  `maxReplayCacheSize` (default 100K entries). When the cache reaches capacity,
  expired entries are force-evicted, then the oldest entry is dropped if still
  full. Prevents unbounded memory growth from long-running servers processing
  many VPs.

- **UUID7 for VP JTI nonces** — `createPresentation()` now generates RFC 9562
  UUID7 nonces instead of UUIDv4. UUID7 embeds a 48-bit millisecond timestamp,
  enabling forensic analysis of audit trails (when was this VP created?) without
  needing to decode the JWT. `generateUuid7()` and `extractUuid7Timestamp()`
  exported from `src/identity/uuid7.ts`.

- **VP audience binding fail-closed** — when `expectedAudience` is set during
  VP verification, a VP with missing `aud` claim is now rejected with
  `WRONG_AUDIENCE` status. Previously, missing `aud` silently passed, allowing
  a VP captured from one server to be replayed against another. The scope engine
  now requires `verifierDid` (non-optional) and always passes it as audience.

- **Agent key persistence** — agent Ed25519 private keys are now AES-256-GCM
  wrapped with the master key and stored alongside agent records in both Postgres
  and SQLite backends. On server restart, `restoreAgents()` loads all persisted
  agents, unwraps keys, recreates signers, and registers public keys with the
  verifier. Agents survive process restarts without re-authentication.
  Migration 003 adds `encrypted_private_key` and `public_key` columns.

### Tests

- 5 new test files (+82 tests, 654 total): `vp-verification.test.ts` (VP
  signature, audience, replay, subject binding), `ceiling-providers.test.ts`
  (Google/Microsoft/AbaxxOne dispatch, provider confusion prevention),
  `server-rest-hardening.test.ts` (session expiry, rate limiting, CORS, OIDC
  alias fallback), `rest-bridge.test.ts` (tool registration, fetch plumbing),
  `delegation.test.ts` (delegation chain, source VC verification, owner walk).

## [0.7.0] — 2026-04-17

### REST Hardening

Six-phase hardening pass closing all gaps identified in the pre-hackathon
review. Every change is fail-closed: new code rejects by default, and
rejection events are auditable.

#### New error types

- **`QueryRejectedError`** — thrown on SQL parse failure, mutation attempt,
  or non-SELECT statement. Replaces the overloaded `CredentialInvalidError`
  for query-level rejections. Code: `QUERY_REJECTED`.

- **`ScopeViolationError`** — thrown when a query references encrypted
  columns outside the credential's scope. Carries `requestedColumns` and
  `authorizedColumns` for internal audit. `toSafeResponse()` coarsens the
  message for HTTP responses (strips column names to prevent schema oracle
  attacks). Code: `SCOPE_VIOLATION`.

- **`CredentialReplayedError`** — thrown on JTI replay detection. Includes
  the replayed JTI and a recovery instruction. Code: `CREDENTIAL_REPLAYED`.

#### Projection boundary (boolean oracle prevention)

- Queries that reference encrypted columns outside the credential's scope
  are now rejected before execution, not just in the SELECT list but in
  WHERE, ORDER BY, HAVING, and JOIN ON clauses. This prevents boolean
  oracle attacks where an attacker infers encrypted values via predicates.

- Only encrypted columns are scope-gated. Unencrypted columns always pass
  through, so agents can still filter and sort by non-sensitive fields.

#### Rejection audit trail

- **`AuditLogger.logRejection()`** — writes V2 rejection records into the
  same hash chain as success records. Fields: `status: 'rejected'`,
  `reason`, `reasonCode`. Optional signer for unsigned rejection records
  (e.g., SQL parse failures before credential verification).

- **V2 audit records** — backward-compatible hash chain. V1 records hash
  the original 10 fields; V2 records include `version`, `status`,
  `reason`, `reasonCode`. `hashAuditRecord()` handles both versions.

- **Async mutex (`chainLock`)** — serializes hash chain operations. Hash
  advances after successful persist, not before, preventing chain
  corruption under concurrent writes.

- Rejected queries are automatically logged. SDK consumers get audit
  trails for both successful and denied access without extra wiring.

#### Production OIDC (Bearer token verification)

- **Bearer token verification** in the REST server replaces the 501 stub.
  Verifies id_tokens via JWKS, extracts scope ceiling from verified claims.

- **`getJwksUri()`** with 1-hour cache and origin validation: the
  `jwks_uri` from OIDC discovery must share the same origin as the
  configured issuer URL (SSRF prevention).

- HTTP error responses now map to correct status codes via a typed
  lookup table (was a fragile inline ternary).

#### Keycloak demo

- **`demo/docker-compose.yml`** — added Keycloak service under the `oidc`
  profile with a preconfigured realm.

- **`demo/keycloak/agents-realm.json`** — realm config with test users,
  client, and scope claim mappers for `scope_columns` and `scope_actions`.

#### expiresIn integer seconds

- `issueCredential()` and `delegateCredential()` now accept
  `expiresIn: number` (seconds) in addition to the existing string format
  (`'4h'`, `'30m'`). Validates against zero, negative, NaN, Infinity,
  and non-integer floats.

### Fixed

- **Fail-closed DB error on agent lookup** — silent `catch {}` on agent
  owner lookup replaced with a `CredentialInvalidError` throw. A database
  outage now rejects the query instead of silently proceeding without
  owner verification.

- **Import ordering** in the REST server — `openApiSpec` import moved
  before `STATUS_BY_CODE` to prevent reference errors.

### Known limitations

- **`/auth/session` OIDC verification** — resolved in v0.8.0. Bearer
  token verification is now the primary auth path in all modes.
  The unverified `oidcIdentity` body-claims path has been removed.

- **Delegation ceiling enforcement** remains in the REST handler, not
  threaded through to the SDK's `delegateCredential()`. Phase 3c.

## [0.6.0] — 2026-04-17

### Added

- **ScopeCeiling** — session-level authorization bound. Every authenticated
  session now carries a `scopeCeiling` declaring which columns and actions
  it may grant in credentials. `issueCredential()` asserts the requested
  scope fits inside the ceiling and throws `ScopeExceedsCeilingError` when
  it doesn't. Closes the class of bug where a client or skill could mint
  broader credentials in-process than its authenticated session permits.

- **`resolveScopeCeilingFromClaims(identity)`** — primary Keycloak-native
  resolver. Reads `scope_columns` and `scope_actions` directly from the
  OIDC token's claims bag. No mapping table on the SDK side; the IdP is
  the authoritative source. Missing claims produce an empty ceiling
  (fail-closed). Wildcard strings (`'*'`) are stripped during resolution —
  reserved for the mock-unrestricted test path only.

- **`resolveScopeCeiling(identity, config)`** — fallback resolver for
  IdPs that emit a `groups` claim but cannot project scope claims
  directly. Maps groups through a caller-supplied `RoleScopeConfig`,
  unions scope across matched groups, drops unknown groups silently
  (a group not in the config contributes nothing — fail-closed).

- **`scopeFitsInCeiling(requested, ceiling)`** — predicate-with-details
  subset check. Returns a tagged union with the excess columns/actions
  on failure, so rejection paths can surface exactly what was out of
  bounds. `assertScopeFitsInCeiling()` wraps it with throw-on-fail.

- **`unrestrictedCeiling()`** — wildcard ceiling tagged
  `source: 'mock-unrestricted'`. Test utility. Audit records distinguish
  mock-unrestricted from real ceilings so "no bounds" is always legible.

- **REST server ceiling enforcement** — `POST /auth/session` resolves
  the ceiling from OIDC claims when `oidcIdentity` is provided and
  surfaces the resolved ceiling in the response body so clients know
  their bounds up-front. `POST /credentials` and
  `POST /agents/:did/delegate` catch `ScopeExceedsCeilingError` and
  return 403 with code `SCOPE_EXCEEDS_CEILING`, naming the exact excess.
  Server-side rejection logging for operator visibility during rollout.

- **Developer handoff pack** (`demo/hackathon/`) — scenarios, challenges,
  upstream-candidate template, and one-command bring-up for an internal
  developer test session. Reuses the Park/Torres capital-markets
  narrative from the AgentScope showcase so both demos tell one story.
  Includes `run.sh` (Postgres bring-up + order_book seed + REST server
  launch with correct env), three adversarial review reports that
  shaped the content, and six open challenges covering credential ops,
  policy-as-code, delegation, non-Node REST access, adversarial scope
  attacks, and the AbaxxOne upgrade path.

- **Cross-agent REST demo transcripts** (`demo/cross-agent/`) — signed
  request/response evidence from a live run of the Park/Torres
  scenarios. Confirms the narrative end-to-end; reviewable in git.

### Changed

- **REST server defaults `NODE_ENV=production`** — was `development`.
  The SDK's mock-auth path (`mockHumanDid`) is gated by
  `NODE_ENV ∈ {development, test}`. Defaulting to `development` meant
  any `agents serve` invocation without explicit env silently enabled
  a forgeable-identity endpoint. Development demos now set
  `NODE_ENV=development` explicitly (see `demo/hackathon/run.sh`);
  production deployments that don't set the env get mock auth
  hard-closed by default.

- **Showcase Beat 4 fallback UX** — when no `ANTHROPIC_API_KEY` is set
  and the user types a custom NL query that doesn't match the canned
  translation map, the UI now surfaces a yellow banner explaining the
  fallback instead of silently returning a generic query whose results
  don't match the user's intent. Canned translation map expanded with
  ten additional common phrasings. Error responses carry real messages
  instead of a generic "Pipeline query failed".

- **Demo ports moved off 3000** — `demo/showcase` now defaults to 3200,
  `demo/quickstart` to 3300. Port 3000 is the universal collision zone
  for local dev environments; both demos previously defaulted to it.
  `PORT` env still overrides. Dockerfiles keep 3000 internal since
  docker-compose maps host→container ports.

### Known limitations

- **`/auth/session` OIDC verification** — resolved in v0.8.0. The REST
  server now verifies Bearer tokens against the OIDC provider's JWKS
  in all modes. The unverified `oidcIdentity` body-claims path has been
  removed.

- **Delegation ceiling enforcement lives in the REST handler, not the
  SDK's `delegateCredential()`.** The SDK's API doesn't currently
  thread session ceilings through to the delegation path, so the
  handler-level check (`packages/server/src/index.ts`) is the minimum
  viable close. Threading the ceiling through to the SDK is Phase 3c.

## [0.5.0] — 2026-04-14

### Added

- **StorageBackend** — abstract persistence layer with Postgres and SQLite implementations.
  Every storage operation flows through identity-gated, auditable channels. Chief (and
  future consumers) can use SQLite locally without bypassing the trust model.

- **IAgentStore, IAuditStore, IContextStore** — decomposed sub-store interfaces.
  Agent store handles registry CRUD. Audit store is append-only with hash chaining
  and database triggers. Context store enforces identity gating at the query level
  (WHERE owner_did = $callerDid) with server identity bypass.

- **IdentityContext** — proof-of-verification token constructed only from
  AgentVerifyResult via createIdentityContext(). Untrusted agents never see this
  directly ... they present bearer tokens that the server verifies on their behalf.

- **SQLite backend** — better-sqlite3 as optional peer dependency. WAL mode,
  append-only triggers, schema parity with Postgres. Available via subpath export
  `@abaxxlabs/agents/sqlite`.

- **createStorageBackend()** factory — discriminated union on type ('postgres' | 'sqlite').
  Dynamic import for SQLite keeps the native dependency optional.

- **Migration 002** — agent_context table with namespace+key composite primary key,
  owner_did indexing, and namespace indexing.

### Changed

- **AuditLogger** now accepts an optional IAuditStore, falling back to pool-based
  Postgres for backward compatibility. Existing callers that pass `{ pool }` continue
  to work with zero changes.

- **package.json** adds subpath exports for `@abaxxlabs/agents/storage` and
  `@abaxxlabs/agents/sqlite`.

### Fixed

- Postgres context store put() now returns actual owner_did from database RETURNING
  clause instead of caller-provided value (prevents stale ownerDid on server upserts).

- PostgresStorageBackend.close() is idempotent (double-close guard).

## [0.4.0] — 2026-04-13

### CapabilityEngine — action-based authorization primitive (T1/T2)

- **`CAPABILITY-SPEC.md`** — language-agnostic specification for CapabilityEngine.
  Defines action format, matching semantics, delegation model, and role expansion.
  Spec-first: Rust implementation remains a future option without spec changes.

- **`CapabilityEngine`** (`src/capability/engine.ts`) — TypeScript implementation of
  the spec. Three operations: `checkCapability(action, scope, capabilitySet)`,
  `isSubsetOf(childSet, parentSet)`, `resolveRole(role, roleMap)`. No external deps.

- **Normalization policy**: actions fully normalized (trim, lowercase, ASCII-only, max 256).
  Scopes partially normalized (trim, max 1024, no null bytes) — case preserved because
  scopes are external resource identifiers (Jira keys, git branches, file paths).

- **Security**: denial reasons never enumerate the granted capability set (oracle risk).
  Malformed caps in a stored set are skipped, not thrown — one bad issuer entry must
  not poison the entire credential check. Malformed requested actions throw (caller bug).

- **Test vectors** (`test/fixtures/capability-vectors.ts`) — 41 canonical vectors +
  boundary/security cases. `bun test test/capability.test.ts`: 50 pass, 0 fail.

### TrustAnchorStore — Layer 2 trusted-issuer management (T4)

- **`LocalTrustAnchorStore`** (`src/discovery/trust-anchor.ts`) — in-memory + keystore-backed
  store for server DIDs trusted to issue binding credentials.

- **Three anchor sources**: `'local'` (own server DID, always trusted, non-removable),
  `'env'` (AGENTS_TRUSTED_SERVERS env var, loaded at construction), `'api'`
  (programmatic adds, persisted to keystore under `agents:trust-anchors`).

- **Event emitter**: `'server-discovered'` (new anchor) and `'server-removed'` (anchor deleted).
  Terminal app mDNS layer can feed into the store while MCP auth layer reacts without polling.

- **`isTrusted(did)`** — O(1) Map lookup. Safe on the MCP request hot path.

- **`createTrustAnchorStore(options)`** — factory typed as `ITrustAnchorStore` interface.

- **Tests** (`test/trust-anchor.test.ts`): 45 pass, 0 fail.

### AgentVerifier — mandatory Layer 2 auth orchestrator (T4b)

- **`AgentVerifier`** (`src/identity/agent-verifier.ts`) — the mandatory single door for all
  MCP agent authentication. MCP handlers MUST call this, never `VcVerifier.verify()` directly.
  Bypassing `AgentVerifier` skips trust and org checks — any server with a valid Ed25519 key
  could issue credentials that pass Layer 1 and access org-scoped resources.

- **Four-check sequence** (in order):
  1. `VcVerifier.verify()` — crypto (signature, expiry, nbf, subject binding, replay)
  2. `TrustAnchorStore.isTrusted(issuerDid)` → `UntrustedIssuerError`
  3. Org boundary: `credentialSubject.orgDomain` vs `expectedOrg` → `WrongOrgError`
  4. `CapabilityEngine.checkCapability(action, scope, caps)` → `AgentUnauthorizedError`

- **New error types**: `UntrustedIssuerError` (code: `UNTRUSTED_ISSUER`), `WrongOrgError`
  (code: `WRONG_ORG`), `AgentUnauthorizedError` (code: `UNAUTHORIZED`). All extend
  `AgentScopeError` with machine-readable `code` and structured `details`.

- **`createAgentVerifier(options)`** — factory typed as `IAgentVerifier` interface.

- **Security hardening** (adversarial review, 2026-04-12):
  - `AgentVerifyRequest.agentDid` changed from optional (`agentDid?: string`) to
    required (`agentDid: string`). An optional field creates a silent bypass — callers
    that omit it skip subject binding with no compile-time or runtime error. Making it
    required forces the confusion-deputy issue to surface at the TypeScript layer before
    it can reach production.
  - Runtime validation of the `capabilities` array (ensure it is truly an array before
    passing to `CapabilityEngine`) deferred to T6 (MCP Bearer Auth). The current cast
    carries acceptable risk: `CapabilityEngine.checkCapability()` skips malformed entries
    and throws `CapabilitySetTooLargeError` for 501+ entries, so a bad cast produces a
    hard error rather than a silent pass. Full schema validation added in T6 when the
    bearer auth middleware is wired.

- **Tests** (`test/agent-verifier.test.ts`): 40 pass, 0 fail. New: SUSPENDED status
  mapping, `CapabilityParseError` propagation, `CapabilitySetTooLargeError` propagation,
  `expectedOrg` whitespace-trim (ops footgun guard), whitespace-only `expectedOrg` TypeError,
  empty-string `agentDid` TypeError (adversarial review guard).

### IDidDhtPublisher interface stub (T5)

- **`IDidDhtPublisher`** + **`DidDhtMethod`** type (`src/identity/did-dht.ts`) — types only,
  no runtime code. Phase 2 always returns `'did:key'`. Phase 3 slots in `DidDhtPublisher`
  class behind this interface without changing calling code. R6 ACCEPTED 2026-04-12:
  pkarr record format still in flux, no production consumers resolving did:dht today.

### MCP Bearer Auth (T6)

- **`McpBearerAuth`** (`src/mcp/auth.ts`) — session token authentication for MCP HTTP transport.
  Validates `Authorization: Bearer <token>` on every `/sse` and `/messages` request.
  Stdio transport skips auth (trusted local pipe).

- **Constant-time comparison** (`timingSafeEqual`) prevents timing side-channel attacks.
  Different-length tokens are compared against a dummy buffer to avoid length leaks.

- **Token rotation** (`OVERLAP_WINDOW_SECONDS = 30`): during binding refresh, both old and
  new tokens are valid. After the overlap expires, the old token is removed.

- **RFC 6750 compliance**: 401 responses include `WWW-Authenticate: Bearer realm="agents-mcp"`.
  Response body is `{ error: 'unauthorized', code: 401 }` with no token hints (oracle prevention).

- **`createMcpBearerAuth(options)`** — factory returning `McpBearerAuth` interface.

- **Tests** (`test/mcp-auth.test.ts`): 35 pass, 0 fail.

### MCP Tool Extensions (T7)

Four new MCP tools exposing the identity layer to connected agents:

- **`whoami`** — returns the current identity bundle: `serverDid`, `humanDid`, `orgDomain`,
  `bindingVcJwt`, `bindingExpiry`, `currentDidMethod` (always `did:key` in Phase 2).

- **`sign`** — sign arbitrary payloads with the server's Ed25519 key. Returns a JWT
  (self-contained, standard verification). **C1 domain separation**: `agents-sign-v1:`
  prefix prepended before the raw payload. 64KB payload size limit.

- **`discover`** — list trusted server DIDs and identity topology. Returns `serverDid`,
  `trustedAnchors` (from TrustAnchorStore), and `didMethod`.

- **`challenge`** — issue HMAC-signed time-based challenges for VP requests. Protocol:
  timestamp+audience+UUID7 (per design memo 2026-03-30, reconfirmed 2026-04-13). Stateless
  issuance. Bounded JTI dedup cache for zero-replay-window protection (E7 atomic consume).

- **`ChallengeStore`** (`src/mcp/challenge-store.ts`) — HMAC-SHA256 challenge issuance with
  UUID7 JTI. `issue()` creates challenges, `consume()` atomically verifies and dedup-caches.
  Max 100 entries, time-based eviction. Per-process random HMAC secret (shared secret
  constructor option for Phase 3 multi-server).

- **Phase 2 tools are conditional** — only registered when `serverIdentity` is provided in
  `ToolDependencies`. Phase 1 deployments get the original 8 tools unchanged.

- **Tests** (`test/mcp-tools-p2.test.ts`): 30 pass, 0 fail.

### Exports

- `CapabilityEngine`, `createCapabilityEngine`, `CapabilityParseError`, `CapabilitySetTooLargeError`,
  `MAX_CAPABILITY_SET_SIZE` — from `src/capability/index.ts`
- `LocalTrustAnchorStore`, `createTrustAnchorStore`, `ITrustAnchorStore`, `TrustAnchor`,
  `TrustAnchorSource` — from `src/discovery/trust-anchor.ts`
- `AgentVerifier`, `createAgentVerifier`, `IAgentVerifier`, `UntrustedIssuerError`,
  `WrongOrgError`, `AgentUnauthorizedError` — from `src/identity/agent-verifier.ts`
- `IDidDhtPublisher`, `DidDhtMethod` — from `src/identity/did-dht.ts`
- `createMcpBearerAuth`, `OVERLAP_WINDOW_SECONDS`, `McpBearerAuth`,
  `McpBearerAuthOptions` — from `src/mcp/auth.ts`
- `ChallengeStore`, `DEFAULT_CHALLENGE_TTL_SECONDS`, `MAX_DEDUP_CACHE_SIZE` — from
  `src/mcp/challenge-store.ts`

---

## [0.3.0] — 2026-04-11

### Phase 1: Generic OIDC + Security Hardening

This release opens agents to any OIDC provider (Google Workspace, Azure AD, Okta, etc.)
via a new provider interface, ships server identity with VC-based binding credentials, and
applies all security findings from the Phase 1 review pass and pre-landing specialist audit.

#### New features

- **Generic OIDC provider** (`src/auth/generic.ts`) — standard OAuth 2.0 + PKCE flow for
  any OIDC-compliant provider. Derives a stable `did:key` humanDid from issuer + sub when
  the provider does not issue DIDs natively.

- **`OidcProvider` interface** (`src/auth/provider.ts`) — two-method design separating
  `parseIdentityFromToken` (pure, no I/O) from `fetchUserInfo` (explicit network call).
  AbaxxOne and Generic are both implementations.

- **`ServerIdentity`** (`src/identity/server-identity.ts`) — server DID + Ed25519 signing key with
  keystore-backed persistence. Survives process restarts.

- **`IdentityBindingCredential`** (`src/identity/binding.ts`) — W3C Verifiable Credential binding
  a server DID to a human OIDC identity. Includes `oauthIssuer` and `oauthSubject` claims
  for verifier provenance.

- **`Keystore`** (`src/identity/keystore.ts`) — secure credential storage with macOS Keychain,
  Linux Secret Service, and encrypted-file fallbacks. Platform auto-selected.

- **`OrgBoundary`** (`src/auth/org-boundary.ts`) — enterprise domain extraction from email,
  `hd` claim (Google), or `tid` claim (Azure). Drives scope boundaries.

- **`PendingFlowStore`** (`src/auth/pending-flow-store.ts`) — PKCE state store for CSRF
  protection in browser OAuth flows. Single-use enforcement, 10-minute TTL, probing-attack
  protection (verifier mismatch does not consume the state).

- **JWKS signature verification** (`src/auth/jwks-verify.ts`) — id_token signature
  verification against the provider's JWKS. Module-level 1-hour cache with automatic
  cache-bust on kid rotation. Validates `exp`, `iss`, and `aud` claims post-signature.
  Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.

- **Mock OIDC server** (`test/mock-oidc-server.ts`) — full in-process OIDC provider for
  integration tests. No AbaxxOne dependency required.

- **MCP server** (`src/mcp/`) — Model Context Protocol wrapper exposing the agents
  library over stdio and SSE transports.

#### Security fixes (Phase 1 /review findings A–E + pre-landing audit)

- **Finding A** — `OidcIdentity.issuer` and `OidcIdentity.sub` are now required fields.
  Previously missing, causing `undefined` values in `IdentityBindingCredential.oauthIssuer`
  and `oauthSubject`, making binding VCs non-verifiable.

- **Finding B** — `verifyIdTokenSignature()` added to both `AbaxxOneOidcProvider` and
  `GenericOidcProvider`. The comment "signature already checked upstream" was incorrect —
  there was no upstream check. JWKS verification is now mandatory before identity extraction.
  Also applied to the legacy `completeOidcFlow()` path.

- **Finding C** — SSRF guard added to all OIDC discovery paths. Discovered endpoints
  (`token_endpoint`, `userinfo_endpoint`) must be HTTPS. Non-HTTPS on non-localhost throws.
  Cross-origin is allowed with a warning (Google pattern). Applied to both new providers
  and the legacy `discoverOidc()` function.

- **Finding D** — PKCE state validation wired into `AbaxxOneOidcProvider.exchangeCode()`
  and `GenericOidcProvider.exchangeCode()`. State is registered at `buildAuthorizationUrl()`
  and consumed (single-use) at `exchangeCode()`. Prevents CSRF in browser redirect flows.
  *Known gap*: legacy `completeOidcFlow()` is a public API and cannot enforce this without
  a signature change — callers are responsible for validating state (documented in module
  header, Finding #6). New providers are the recommended path.

- **Finding E** — DID method validation in legacy `completeOidcFlow()`: only `did:key:`
  and `did:dht:` are accepted. Any other method (did:web, did:ion, numeric sub) throws.
  Pattern mirrors existing check in `AbaxxOneOidcProvider.fetchUserInfo()`.

- **JWT claims validation** — `verifyIdTokenSignature()` now validates `exp` (always),
  `iss` (if `expectedIssuer` provided), and `aud` (if `expectedAudience` provided) after
  signature verification. Both new providers pass these. Prevents token replay from other
  issuers or clients.

#### Bug fixes

- `keystore.delete()` was silently a no-op on the macOS Keychain backend — now calls
  `security delete-generic-password` correctly.
- `OrgBoundary` domain-cache was keyed on email string but looked up with decoded JWT
  claims object — cache never hit. Fixed key to normalize on email string.
- Scope engine returned `WRONG_SUBJECT` for valid agent+scope combinations when the VC
  subject DID used `did:key` with an uppercase hex prefix. Normalization added.
- Empty-catch blocks in several files replaced with typed catches or intentional ignores
  with comments.

#### Known follow-on items (tracked for v0.3.x)

- Unit tests for `PendingFlowStore` and `jwks-verify` (SSRF, exp/iss/aud failure paths)
- `PendingFlowStore` max-size cap (unbounded memory DoS under adversarial state flooding)
- Algorithm allowlist in `jwks-verify` (currently accepts any alg header value)
- Consolidate duplicated `base58Encode` (Decision #18: `generic.ts` + `src/auth.ts` → `src/crypto/base58.ts`)
- `deriveHumanDid()` public key usage audit

## [0.2.0] — prior

Initial AbaxxOne-only release with OIDC flow, VC verification, and scope engine.
