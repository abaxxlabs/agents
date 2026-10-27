# Changelog

## [0.50.2] - 2026-10-27

### Fixed

- Add exception to codeowners employee names
- demo: internal changes.
- demo: internal changes.

## [0.50.1] - 2026-10-27

### Fixed

- repository: changes; .github, packages, private, scripts: internal changes.

## [0.50.0] - 2026-10-27

### Added

- .github, packages: internal changes.

## [0.49.0] - 2026-10-26

### Added

- .github, docs-site, scripts, test: internal changes.

## [0.48.2] - 2026-10-26

### Fixed

- src, test: changes; demo, scripts, test: internal changes.

## [0.48.1] - 2026-10-26

### Fixed

- src, test: changes; docs, scripts, test: internal changes.

## [0.48.0] - 2026-10-23

### Added

- .github, docs-site: internal changes.

## [0.47.0] - 2026-10-22

### Added

- src, test: changes; demo, repository: internal changes.

## [0.46.1] - 2026-10-22

### Fixed

- reject credentials without an expiry

## [0.46.0] - 2026-10-20

### Added

- demo: internal changes.

## [0.45.0] - 2026-10-20

### Added

- demo: internal changes.

## [0.44.0] - 2026-10-20

### Added

- demo: internal changes.

## [0.43.0] - 2026-10-19

### Added

- .github, demo, packages: internal changes.
- derive did:dht keys offline when no resolver is configured
- docs-site: internal changes.
- export AuthorizationUrlResult from the package root
- expose buildAuthorizationUrl on AgentScope
- src, test: changes; test: internal changes.


### Fixed

- .github, packages: internal changes.
- .github: internal changes.
- .github: internal changes.
- add missing declarations on AgentScopeInstance
- export DelegationExpiryExceedsParentError from the package root
- repository, scripts: changes; .github, repository, scripts: internal changes.
- repository: internal changes.
- scripts: changes; .github, packages, scripts: internal changes.
- scripts: changes; .github, packages: internal changes.
- surface a malformed did:dht identifier as a resolution failure

## [0.42.1] - 2026-10-13

### Fixed

- Excluded a site-only test from the distributed source checkout.

## [0.42.0] - 2026-10-13

### Added

- Added assertions that out-of-scope queries are rejected before database execution.
- .github: internal changes.

## [0.41.0] - 2026-10-09

### Added

- demo: internal changes.

## [0.40.0] - 2026-10-08

### Added

- rename createAgent to createAgentIdentity and create-agent to create-agent-identity

## [0.39.1] - 2026-10-07

### Fixed

- Clarified MCP presentation creation, identity SDK integration, and key-migration guidance.

## [0.39.0] - 2026-10-06

### Added

- Removed database connection details and underlying storage errors from SDK error responses.

## [0.38.2] - 2026-10-02

### Fixed

- scripts: internal changes.

## [0.38.1] - 2026-09-29

### Fixed

- block private package paths in public sync

## [0.38.0] - 2026-09-29

### Added

- demo: internal changes.

## [0.37.0] - 2026-09-28

### Added

- Credit imported contributors in public Sync commits
- enforce public mirror documentation boundary
- enforce the public mirror boundary
- make changelog canonical for public release
- scripts: internal changes.

### Fixed

- keep private packages out of the public mirror
- remove stale public mirror files
- use TypeScript ESLint config in public mirror
- validate publication licenses and reject unstaged changes
- verify generated public checkout independently

## [0.36.1] - 2026-09-28

### Fixed

- Distinguished scoped audit-chain visibility gaps from global chain corruption.

## [0.36.0] - 2026-09-24

### Changed

- Moved delegation claims into the `vc` object.

## [0.35.0] - 2026-09-23

### Changed

- demo: internal changes.

## [0.34.3] - 2026-09-21

### Fixed

- packages: internal changes.

## [0.34.2] - 2026-09-14

### Fixed

- packages: internal changes.

## [0.34.1] - 2026-09-14

### Fixed

- demo: internal changes.

## [0.34.0] - 2026-09-10

### Added

- demo: internal changes.

## [0.33.1] - 2026-09-09

### Fixed

- packages: internal changes.

## [0.33.0] - 2026-09-09

### Changed

- demo: internal changes.

## [0.32.0] - 2026-09-09

### Added

- demo: internal changes.

## [0.31.0] - 2026-09-07

### Added

- demo: internal changes.

## [0.30.1] - 2026-09-03

### Fixed

- .github: internal changes.

## [0.30.0] - 2026-09-02

### Added

- demo: internal changes.

## [0.29.0] - 2026-08-28

### Added

- demo: internal changes.

### Changed

- Kept private applications and their references outside public source synchronization.

## [0.28.1] - 2026-08-28

### Fixed

- demo: internal changes.

## [0.28.0] - 2026-08-27

### Added

- Recorded delegation provenance in audit records.

### Fixed

- Enforced strict delegated provenance validation in audit checks.

## [0.27.7] - 2026-08-27

### Changed

- Migrated GitHub workflows off Node.js 20.

## [0.27.6] - 2026-08-26

### Changed

- Reorganized repository documentation into concept, guide, interface, security, and migration sections.

## [0.27.5] - 2026-08-26

### Added

- packages: internal changes.

## [0.27.4] - 2026-08-26

### Changed

- Upgraded the CodeQL workflow actions to version 4.

## [0.27.3] - 2026-08-25

### Fixed

- Unblocked generated public source checks.

## [0.27.2] - 2026-08-25

### Fixed

- Excluded tests coupled to private infrastructure from public source synchronization.

## [0.27.1] - 2026-08-25

### Added

- packages: internal changes.

## [0.27.0] - 2026-08-25

### Added

- docs-site: internal changes.

## [0.26.1] - 2026-08-25

### Fixed

- docs-site: internal changes.

## [0.26.0] - 2026-08-25

### Added

- packages: internal changes.

## [0.25.0] - 2026-08-25

### Added

- docs-site: internal changes.

## [0.24.0] - 2026-08-25

### Added

- packages: internal changes.

## [0.23.2] - 2026-08-25

### Added

- packages: internal changes.

## [0.23.1] - 2026-08-25

### Security

- packages: internal changes.

## [0.23.0] - 2026-08-24

### Added

- Added the owner-bound `createPresentationForAgent()` API.

## [0.22.2] - 2026-08-24

### Fixed

- Normalized presentation audit hashes to the inner Verifiable Credential.

## [0.22.1] - 2026-08-24

### Fixed

- Emitted one revocation telemetry event per credential check.

### Security

- Enforced delegated-credential ancestor revocation using credential identifiers and hashes.

## [0.22.0] - 2026-08-24

### Added

- Added installation, overview, quick-start, interface, and security reference material to the repository documentation.

## [0.21.3] - 2026-08-24

### Fixed

- Removed unused scoped-query instance state.

## [0.21.2] - 2026-08-21

### Fixed

- Moved `AgentScope` into its own module.

## [0.21.1] - 2026-08-21

### Fixed

- Aligned scoped-query documentation with projection enforcement.

## [0.21.0] - 2026-08-21

### Fixed

- Updated identity tool registration to use `registerTool`.
- docs-site: internal changes.

## [0.20.4] - 2026-08-21

### Fixed

- Persisted v3 audit columns in the SQLite store.
- Pinned the Bun version in the JSDoc workflow.
- test: internal changes.

## [0.20.3] - 2026-08-20

### Fixed

- Centralized first-party license notices.
- Updated tests and repository guidance for centralized notices.

## [0.20.2] - 2026-08-20

### Fixed

- packages: internal changes.

## [0.20.1] - 2026-08-19

### Fixed

- Replaced deprecated MCP tool and resource registration APIs.

## [0.20.0] - 2026-08-19

### Added

- docs-site: internal changes.

## [0.19.1] - 2026-08-19

### Fixed

- Keyed MCP rate limits by authenticated human identity so switching agents cannot bypass a human's limit.

## [0.19.0] - 2026-08-13

### Changed

- demo: internal changes.

## [0.18.0] - 2026-08-13

### Added

- demo: internal changes.

## [0.17.0] - 2026-08-13

### Changed

- demo: internal changes.

## [0.16.0] - 2026-08-13

### Added

- demo: internal changes.

## [0.15.5] - 2026-08-13

### Fixed

- Hardened JWT NumericDate validation.

## [0.15.4] - 2026-08-13

### Fixed

- Routed MCP resources through transport-neutral services.

## [0.15.3] - 2026-08-11

### Changed

- Reorganized repository contributor guidance.

## [0.15.2] - 2026-08-10

### Changed

- Split `ScopeEngine` query processing into focused authorization, execution, and result-assembly modules without changing its public API.
- Updated documentation for the query-module decomposition.

## [0.15.1] - 2026-08-10

### Changed

- Split the MCP tool implementation into domain-focused modules and updated its coverage.

## [0.15.0] - 2026-08-10

### Added

- demo: internal changes.

## [0.14.14] - 2026-08-07

### Fixed

- Ensured the public artifact audit runs when invoked directly from the command line.

### Changed

- Documented query execution as validation followed by execution, with out-of-scope references rejected rather than returned as ciphertext.
- Documented wildcard projection rejection and projection checks across `SELECT`, `WHERE`, `ORDER BY`, `HAVING`, and `JOIN ON` references.
- Distinguished mutation parse errors from scope-violation errors.
- Separated issuance-time delegation narrowing from query-time signature, revocation, depth, and binding verification.
- Documented bearer-token validation for every MCP HTTP request and development-only unauthenticated startup behavior.
- demo: internal changes.

## [0.14.13] - 2026-08-05

### Fixed

- Rejected scoped queries when read authorization is absent.
- Removed redundant explanatory comments from the scoped-query path.

## [0.14.12] - 2026-08-05

### Fixed

- Aligned the scoped-query credential contract and clarified its code commentary.

## [0.14.11] - 2026-08-05

### Fixed

- Extended `SessionEnvelope` with optional OIDC identity and scope-claim metadata.
- packages: internal changes.

## [0.14.10] - 2026-08-04

### Removed

- demo: internal changes.

## [0.14.9] - 2026-07-29

### Fixed

- Hardened public artifact auditing and release provenance checks.

## [0.14.8] - 2026-07-24

### Fixed

- Included tests in public source synchronization.

## [0.14.7] - 2026-07-24

### Fixed

- Aligned public source synchronization with release guardrails.

## [0.14.6] - 2026-07-23

### Fixed

- Improved error handling and logging in SQLite and PostgreSQL storage backends.
- Reorganized storage modules for clarity and performance.

## [0.14.5] - 2026-07-08

### Fixed

- demo: internal changes.

## [0.14.4] - 2026-07-06

### Fixed

- Included lint and build configuration in public source synchronization.

## [0.14.3] - 2026-07-06

### Fixed

- Corrected continuous-integration files included in public source synchronization.

## [0.14.2] - 2026-07-06

### Fixed

- private: internal changes.

## [0.14.1] - 2026-07-06

### Fixed

- demo: internal changes.

## [0.14.0] - 2026-06-29

### Added

- scripts: internal changes.

## [0.13.3] - 2026-06-26

### Fixed

- packages: internal changes.

## [0.13.2] - 2026-06-12

### Fixed

- Allowed a newline between audit tokens and severity markers during source synchronization.
- Preserved newlines when filtering synchronized content.

## [0.13.1] - 2026-06-12

### Fixed

- Excluded the package version from public API snapshots.

## [0.13.0] - 2026-06-12

### Added

- demo: internal changes.

## [0.12.7] - 2026-06-12

### Fixed

- Corrected a credential-issuance documentation link from a JavaScript extension to TypeScript.

## [0.12.6] - 2026-06-11

### Fixed

- Authorized automated release publication through the designated application identity.
- Verified semantic-release tag generation.

## [0.12.5] - 2026-06-10

### Removed

- Removed the unused `ScopeWarning` error class, which was not part of a public entry point.

### Fixed

- Exported `SqliteRuntimeUnavailableError` from the root and SQLite public subpaths.
- Restored CommonJS compatibility by using dual ESM and CommonJS versions of `jose` and `uuid`.

### Changed

- Returned the Node.js engine floor to `>=20.3.0` after restoring dual-module dependencies.
- Documented `IssueCredentialOptions.maxDepth` defaults, valid range, and thrown validation error.
- test: internal changes.

## [0.12.4.0] - 2026-05-26

### Added

- demo: internal changes.

## [0.12.3.0] - 2026-05-22

### Added

- Added optional `maxDepth` support to the MCP `issue-credential` tool, defaulting to 2 and accepting integers from 1 through 10.
- Updated the source-only MCP REST-bridge descriptor for `maxDepth`.
- demo: internal changes.

## [0.12.2.0] - 2026-05-21

### Fixed

- Embedded caller-specified `maxDepth` values in credentials issued through the SDK path.
- Forwarded `maxDepth` through parent-provider credential issuance.

## [0.12.1.0] - 2026-05-20

### Fixed

- Declared the runtime required for the CommonJS entry point and verified all seven public subpaths under that runtime.

### Breaking

- Raised `engines.node` from `>=20.3.0` to `>=22.12.0` and moved continuous integration to Node.js 22.

## [0.12.0.0] - 2026-05-20

### Added

- Cached imported JWT signing and verification `CryptoKey` objects in bounded 256-entry LRU caches.
- Reused derived Ed25519 public keys for repeated signatures.

### Fixed

- Made `connectIdSdkMcp()` work after a single package installation by declaring its transitive runtime dependencies at the package root.
- Reported optional native dependency failures by dependency name instead of surfacing opaque module-loading errors.
- Hardened `--master-key-stdin` with interactive-TTY rejection and a 1 KiB input cap.
- src: internal changes.

### Changed

- Made new audit records V3 while retaining V1 and V2 chain verification.
- Clarified that local-key and SDK-enhanced credential issuance are both first-class paths.
- Accepted a larger installation footprint so the ID SDK MCP integration works without manual dependency installation.
- Promoted `@modelcontextprotocol/sdk` from optional to required dependency status.
- Removed `--master-key <hex>` and `--master-key=<hex>`; keys now come from `AGENTS_MASTER_KEY` or `--master-key-stdin`.

### Removed

- Removed the vestigial root-entry `AgentScope` wrong-subpath proxy.
- Removed the legacy encryption-only scope mode, its environment gate, and `LegacyScopeModeNotAllowedError`; projection mode is now the only scope mode.
- Removed legacy OIDC entry points and related public auth exports; `AgentIdentity` now delegates OIDC flows through `AbaxxOneOidcProvider`.

### Security

- Made audit writes fail closed unconditionally and removed all `failOpen` options and telemetry fields.
- Hashed private key bytes before using them as signer-cache keys.
- Cached verifier public keys only after successful signature verification to resist cache eviction attacks.
- Required `SqliteStorageBackend` callers to supply an HKDF-derived `sessionMacKey`.
- Required OAuth callback `state` in `AgentIdentity.completeAuthentication` and `AgentScope.completeAuthentication`, with single-use pending-flow validation before token exchange.
- Removed configuration-level delegation ceilings; root credentials now carry `IssueCredentialOptions.maxDepth`, inherited by descendants.
- Removed `operatorMaxDepth` from `issueDelegatedCredential`; the parent credential is authoritative.

### Breaking

- Removed the legacy encryption-only scope mode and legacy OIDC entry points from the public API.
- Required `SqliteStorageBackend` callers to supply `sessionMacKey`.
- Required OAuth callback `state` in `AgentIdentity.completeAuthentication` and `AgentScope.completeAuthentication`.
- Removed configuration-level delegation ceilings and the `operatorMaxDepth` argument.

## [0.11.6.0] - 2026-05-12

### Added

- Exported `TtlExceededError` from the public API.

### Fixed

- Unified credential TTL validation to throw `TtlExceededError`.
- Bounded duration parsing and related regular expressions to resolve polynomial regular-expression denial-of-service risks.
- Replaced connection-string masking regex logic with index-based parsing.

## [0.11.4] - 2026-04-30

Release label: `0.11.4.0`.

### Added

- Added branded `Did`, `ColumnName`, `TableName`, `Jti`, and `IssuerUrl` domain types with boundary factories.
- Added focused coverage for the extracted modules and edge cases.

### Changed

- Split scope query validation, delegation validation, JWT utilities, DID resolution, authentication operations, and storage contracts into single-responsibility modules while preserving public import paths.
- Consolidated the strongly typed `IdSdkInstance` definition and limited type assertions to the MCP transport boundary.
- Marked the legacy OIDC module deprecated for removal at version 1.0.

### Fixed

- Removed accidental public exports for `generateDidKeyFromSeed`, `base64UrlDecode`, and `base64UrlEncode`.

## [0.11.3] - 2026-04-29

Release label: `0.11.3.0`.

### Added

- Added package smoke tests for CommonJS and ESM loading across every public subpath.
- Added assertions that package metadata and executable declarations point to built tarball artifacts.
- Added an npm cache ownership guard before package verification and publication checks.
- Added public artifact scanning for restricted paths, oversized text, and high-confidence secrets.
- Separated deterministic default tests from explicitly enabled platform and network integration tests.
- Added public API export snapshots for the six supported package subpaths.
- Added MCP import smoke tests that do not require SQL peer dependencies.
- docs: internal changes.

### Changed

- Standardized public package metadata and documentation on `@abaxxlabs/agents`.
- Exactly pinned runtime, optional, and peer dependency versions for the release.

### Fixed

- Restored CommonJS loading for the SQL and MCP subpaths by avoiding parse-time `import.meta` syntax in CommonJS output.
- Preserved the built CLI artifact so the published `agents` binary resolves correctly.
- Updated tests to assert current wrong-master-key behavior and source layout.

## [0.11.2.0] - 2026-04-29

### Added

- Added branded `TrustedMigrationCredential` and `VerifiedParentCredential` types.
- Added trust-anchor smart constructors that reject untrusted JWT issuers.
- Exported `decodeJwtIssuer()` for shared issuer extraction without signature verification.
- Added `MigrationExecutor.migrationTrustAnchor` for smart-constructor use.
- Added a regression test proving the runtime trust gate survives a TypeScript brand cast.

### Changed

- Narrowed `MigrationExecutor.execute()` to `TrustedMigrationCredential` while retaining runtime verification for JavaScript and cast bypasses.
- Removed project-specific references from source comments.

## [0.11.1]

### Added

- Extended `parseDuration` to compound, fractional, and millisecond values while continuing to reject bare numbers, unknown units, trailing data, and duplicate units.
- Allowed `CreatePresentationOptions.audience` to be a string or string array.

### Fixed

- Made filtered audit-chain verification anchor at the first returned record and report whether verification is partial.
- Rejected non-finite, negative, and approximately century-scale duration values.
- Preserved `orgId` when audit export and chain verification expand DID aliases.
- Restored branded migration credentials while retaining runtime trust verification.

### Changed

- Filtered audit-chain verification can contain non-consecutive records; use unfiltered verification for absolute root-of-chain proof.

## [0.11.0]

### Added

- Added the SQL-free `AgentIdentity` class for DID, credential, agent, OIDC, and audit operations.
- Added root, SQL, MCP, storage, SQLite, and bootstrap package subpaths.
- Added `AgentStore.listAll()`, `AgentStore.count()`, and `AuditStore.count()`.
- Added a root-import isolation test that excludes PostgreSQL and SQL parser loading.

### Changed

- Removed unused pool parameters from authentication factories.
- Moved agent persistence behind `AgentStore` and audit persistence behind `AuditStore`.
- Limited `ScopeEngine` pool use to data-plane query execution and used `AgentStore` for owner lookup.

### Breaking

- Moved `AgentScope`, `ScopeEngine`, `ScopeMode`, and SQL column-key helpers to `@abaxxlabs/agents/sql`.
- Made the SQL-free `AgentIdentity` class the root entry point's primary identity API.
- Moved MCP server exports to `@abaxxlabs/agents/mcp`.
- Made `libpg-query` an optional peer dependency for SQL consumers.
- Renamed the agent-record interface from `AgentIdentity` to `RegisteredAgent`.

## [0.10.1]

### Added

- Added `CreatePresentationOptions.lifetime` with validated duration strings and a one-second minimum.

### Changed

- Reduced the default Verifiable Presentation lifetime from 300 seconds to 60 seconds; callers needing a longer window must set `lifetime` explicitly.
- Clarified that `VcVerifierOptions.clockSkew` applies to credential and presentation timestamps and extends replay-cache retention.

## [0.10.0] - 2026-04-26

### Added

- Added `AgentScopeConfig.devMode`, `AgentScopeConfig.keystore`, and `AgentScopeConfig.orgBoundary.extraConsumerDomains`.
- Added public `composeConsumerDomains()` and bootstrap `resolveTrustedServersFromEnv()` helpers.
- Added `LocalTrustAnchorStore.initialTrustedServers` and the `SCOPE_MODE_LEGACY` constant.
- Extended `agents migrate-check` with advisories for migrated environment configuration.
- Added startup warning behavior for production MCP deployments using the default non-coherent revocation backend.
- Added regression coverage proving explicit consumer configuration wins over five migrated environment variables.

### Changed

- Moved development-mode environment bridging to the MCP boundary while retaining production guards.
- Unified consumer-domain classification; additional public email domains are now treated as consumer identities rather than organizations, so previously authenticated identities from those domains can fail organization assertions after upgrade.

### Breaking

- Changed `createKeystore(customPath?)` to `createKeystore({ customPath?, devMode? })`.
- Replaced library reads of `AGENTS_DEV_MODE` with `AgentScopeConfig.devMode`.
- Replaced library reads of `AGENTS_KEYSTORE_PATH` with `AgentScopeConfig.keystore.path`.
- Replaced library reads of `AGENTS_CONSUMER_DOMAINS` with explicit extra-domain options shared by `OrgBoundary`, `GenericOidcProvider`, and binding credentials.
- Replaced library reads of `AGENTS_TRUSTED_SERVERS` with explicit `LocalTrustAnchorStore.initialTrustedServers` input.
- Renamed the legacy scope-mode value to `encryption-only-LEGACY-DO-NOT-USE` and removed its environment gate.

## [0.9.10.0] - 2026-04-25

### Added

- Added the branded `MasterKey` type and validating `asMasterKey()` constructor.
- Added `AgentScope.pruneRevocations()`, `VcVerifier.isRevoked()`, and `composeStorageBackend()`.
- Added `@abaxxlabs/agents/bootstrap` helpers for strict master-key parsing and environment bootstrap.
- Added `verifyAllColumnKeys()` for non-mutating master-key migration diagnostics.
- Added compile-time checking of TypeScript examples embedded in public JSDoc.
- Added a read-only `agents migrate-check` scanner for legacy master-key integration patterns.
- packages: internal changes.

### Changed

- Distinguished missing schemas from wrong-key decryption in column-key and agent restoration.
- Passed master keys explicitly through CLI initialization and demo setup without environment mutation.
- Retained `StorageBackend.sessions` and the verifier getter while providing sanctioned revocation methods.

### Security

- Wired revocation-store injection so durable and multi-instance revocation backends are actually enforced.
- Versions `0.9.6.0` through `0.9.9.0` exposed revocation adapters but always used process-local memory; revocations in those versions were not durable across restarts or visible across instances.
- Made `VcVerifierOptions.revocationStore` required and made the type system reject verifier construction without one.
- Removed library reads of `AGENTS_MASTER_KEY`; callers now inject a branded master key.
- Made wrong-key startup fail with `MasterKeyMismatchError` instead of returning encrypted placeholders.
- Redacted key material from inspection and JSON serialization and zeroed primary key buffers on close.
- Added static restrictions against direct master-key environment reads in library code.

### Breaking

- Changed `AgentScope.create(config)` to required `AgentScope.create(config, injections)` with `injections.masterKey`.
- Removed the master key from `AgentScopeConfig.encryption`.
- Made verifier revocation storage explicit and retained an in-memory default only at the `AgentScope` factory boundary.
- Kept duplicate column registration as an error and updated `MasterKeyMissingError` guidance.

## [0.9.9.0] - 2026-04-24

### Added

- Added `rotateColumnKey()` with rollback-safe row migration and per-column serialization.
- Added `rewrapColumnKey()` for changing a master key without changing row ciphertext.
- Added `KeyRotationFailedError` and `KeyRotationPhase` with precise failure stages and preserved causes.

### Changed

- Changed duplicate column registration from an upsert to a clear error directing callers to rotation or rewrapping.
- Left write quiescence, authorization, and large-table batching as caller-controlled policies.

### Security

- Added atomic column-key rotation that decrypts and re-encrypts rows, swaps wrapped keys, and appends audit evidence in one transaction.
- Prevented duplicate `registerColumn()` calls from silently replacing a key and making existing ciphertext unreadable.

## [0.9.8.0] - 2026-04-24

### Added

- Added `ISessionStore` with memory, PostgreSQL, and SQLite adapters.
- Added size-bounded `SessionEnvelope` records protected by HMAC-SHA256 over canonical JSON with an HKDF-derived key.
- Added migration 008 for expiring sessions and human-DID deletion support.
- Added session-store pruning and deletion by human DID.
- Added bounded PostgreSQL read-through caching and per-token singleflight request coalescing.
- packages: internal changes.

### Changed

- Enabled SQLite WAL mode with `synchronous = NORMAL` across adapters.

## [0.9.6.0] - 2026-04-23

### Added

- Added `IRevocationStore` with memory, PostgreSQL, and SQLite adapters.
- Added migration 007 for expiring revoked credentials.
- Added fail-closed asynchronous `VcVerifier.revokeAsync()`.
- Added row-level locking for revocation reads.

### Changed

- Made local revocation storage authoritative and external SDK notification best effort.
- Changed `AuthenticatedSession.revokeCredential()` to reject on storage failure and return an optional notification failure.

### Security

- Added durable credential revocation with a default 30-second cross-instance visibility bound.
- packages: internal changes.

### Breaking

- Made `revokeCredential()` asynchronous and fail closed on storage errors.
- Changed its return type from `Promise<void>` to `Promise<{ sdkNotificationFailed?: Error }>`.

## [0.9.5.0] - 2026-04-23

### Fixed

- Serialized audit chain-head reads during initialization to prevent concurrent processes from forking the hash chain.
- Compared audit hashes with length-checked constant-time equality.

## [0.9.4.0] - 2026-04-23

### Fixed

- Required explicit opt-in before constructing the legacy encryption-only scope mode.
- Validated time-of-day policy timezones against supported IANA values and cached the supported set.
- Added optional ceiling enforcement to parent-provider credential issuance before contacting the provider.
- Restricted `createMockSession()` to development and test environments, treating an unset environment as production.

## [0.9.3.0] - 2026-04-23

### Added

- Added timezone-authoritative time-of-day issuance rules for scope ceilings.
- Added audit hash-chain verification with structured success and failure positions.

### Fixed

- Validated scoped-query table identifiers, checked agent persistence results, and made mock identities stable across authentication calls.
- Improved wrong-key diagnostics and skipped unreadable legacy column keys during startup.
- Made storage initialization surface migration SQL failures.
- demo: internal changes.
- packages: internal changes.

## [0.9.2.0] - 2026-04-19

### Added

- Added organization-issued parent credentials with local-signing fallback when the parent provider is unavailable.
- Added ephemeral parent trust anchors that cannot overwrite persistent anchors.
- Enforced parent capability ceilings before agent credentials are accepted.
- Added V3 audit records with optional `orgId` and indexed organization filtering in PostgreSQL and SQLite.
- demo: internal changes.

### Fixed

- Limited parent-credential fallback to the expected request failure instead of swallowing unrelated errors.
- Removed an empty-capability guard that bypassed parent ceiling checks.
- Preserved empty-string `orgId` values in signed audit records.

## [0.9.1.1] - 2026-04-18

### Changed

- demo: internal changes.

## [0.9.1.0] - 2026-04-18

### Added

- Made projection scope mode the default so every referenced column, encrypted or not, must be credential-authorized.
- Added capability-gating errors with actionable capability and namespace details.

### Fixed

- Centralized and runtime-validated `ScopeMode` values.
- Corrected table-qualified SQL column extraction.
- Preserved capability-gating error details through MCP error mapping.

## [0.9.0] - 2026-04-18

### Added

- Added DID identity migration detection and atomic ownership transfer with a grace period for old and new DIDs.
- Added bidirectional DID aliases and alias-aware scope ownership, delegation, and issuer checks.
- Added migration-credential detection in Verifiable Presentations with a `MIGRATION_DETECTED` result.
- Added alias-expanded audit export for PostgreSQL and SQLite.
- Added migration 004 for persisted DID aliases and credential-hash lookup.

### Changed

- Credential re-issuance after DID migration remained unsupported; existing credentials continued to require their original issuance lifecycle.

## [0.8.0] - 2026-04-18

### Added

- Added the MCP `delegate-credential` tool with source-subset and session-ceiling enforcement.
- Added signed Verifiable Presentations with nonce replay protection, optional audience binding, expiry, and automatic wrapping of raw credentials.
- Added `WRONG_AUDIENCE` verification results and fail-closed audience enforcement when the audience claim is missing.
- Added bounded replay caching and UUID7 presentation identifiers with timestamp extraction.
- Added encrypted agent private-key persistence and agent restoration across restarts through migration 003.
- demo: internal changes.
- packages: internal changes.

### Changed

- Made delegated credential creation asynchronous and verified the source credential and full owner chain.

### Security

- Replaced substring provider dispatch with exact issuer-hostname matching.

### Fixed

- Replaced empty-string presentation nonces with generated nonces.
- Added `WRONG_AUDIENCE` to the verification result type.

## [0.7.0] - 2026-04-17

### Added

- Added `QueryRejectedError`, `ScopeViolationError`, and `CredentialReplayedError` with safe external responses.
- Rejected out-of-scope encrypted column references in projections, predicates, ordering, grouping, and joins before execution.
- Added V2 audit rejection records, backward-compatible hashing, and serialized chain updates after successful persistence.
- demo: internal changes.
- packages: internal changes.
- Allowed positive integer-second `expiresIn` values in addition to duration strings.

### Fixed

- Made database failures during agent-owner lookup reject queries instead of bypassing owner verification.

## [0.6.0] - 2026-04-17

### Added

- Added session-level `ScopeCeiling` authorization for credential issuance.
- Added fail-closed scope ceiling derivation from direct OIDC scope claims and caller-defined group mappings.
- Added detailed subset checks and a mock-only unrestricted ceiling marker.
- demo: internal changes.
- packages: internal changes.

## [0.5.0] - 2026-04-14

### Added

- Added the identity-gated `StorageBackend` abstraction with PostgreSQL and SQLite implementations.
- Added separate agent, append-only audit, and owner-scoped context store interfaces.
- Added `IdentityContext` values constructible only from verified agent results.
- Added an optional-peer SQLite backend with WAL mode and schema parity.
- Added the `createStorageBackend()` factory and storage and SQLite package subpaths.
- Added migration 002 for namespaced, owner-indexed agent context.

### Changed

- Allowed `AuditLogger` to use an audit store while retaining pool-based PostgreSQL compatibility.

### Fixed

- Returned the persisted context owner from PostgreSQL upserts.
- Made `PostgresStorageBackend.close()` idempotent.

## [0.4.0] - 2026-04-13

### Added

- Added `CapabilityEngine` checks, subset evaluation, and role resolution with bounded input normalization.
- Added capability denial behavior that avoids revealing granted capabilities and skips malformed stored entries.
- Added `LocalTrustAnchorStore` with local, environment-bootstrap, and API anchor sources, persistence, and discovery events.
- Added `AgentVerifier` as the mandatory composition of credential verification, issuer trust, organization boundary, and capability checks.
- Added structured untrusted-issuer, wrong-organization, and unauthorized-agent errors.
- Made the requested agent DID mandatory for verification to prevent silent subject-binding bypass.
- Added DID DHT publisher interface types for future method support.
- Added MCP bearer authentication on every SSE and message request, constant-time token comparison, 30-second rotation overlap, and RFC 6750 responses.
- Added conditional MCP `whoami`, `sign`, `discover`, and `challenge` tools for configured server identities.
- Added domain-separated Ed25519 signing with a 64 KiB payload cap.
- Added bounded, atomic HMAC challenge issuance and consumption with UUID7 identifiers.
- docs: internal changes.

## [0.3.0] - 2026-04-11

### Added

- Added a generic OAuth 2.0 and PKCE OIDC provider with stable human DID derivation.
- Added the `OidcProvider` interface separating pure token parsing from network user-info retrieval.
- Added persistent Ed25519 `ServerIdentity` and W3C identity-binding credentials with issuer provenance.
- Added platform-selected secure keystore support for macOS, Linux, and encrypted files.
- Added organization-boundary extraction from email and common provider claims.
- Added single-use, expiring PKCE state storage resistant to verifier probing.
- Added cached JWKS signature and claim verification with key-rotation recovery and a bounded algorithm set.
- Added a self-contained OIDC test provider and MCP stdio and SSE transports.

### Security

- Required OIDC issuer and subject fields in identity values and binding credentials.
- Made ID-token signature, expiry, issuer, and audience verification mandatory before identity extraction.
- Required HTTPS discovered OIDC endpoints except for local development and warned on cross-origin discovery.
- Enforced PKCE state validation in provider authorization-code exchanges.
- Restricted legacy OIDC DID methods to `did:key` and `did:dht`.

### Fixed

- Made macOS keystore deletion invoke the platform credential deletion command.
- Corrected organization-domain cache keys.
- Normalized DID key subjects before scope verification.
- Replaced silent exception handling with typed or explicitly ignored failures.

## [0.2.0] - prior

### Added

- Added the initial AbaxxOne OIDC flow, Verifiable Credential verification, and scoped query engine.
