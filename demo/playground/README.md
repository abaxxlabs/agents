# Demo: Agents++ — Order Book with per-agent scoped access

Real integration with [`@abaxxlabs/agents`](https://github.com/abaxxlabs/agents), linked directly to this repository's package.

**Use case:** a trading desk lets an AI agent query its order book. The human authenticates, creates the agent (Ed25519 keypair + DID) and issues it a credential that defines exactly which columns it can see and for how long. `price` and `counterparty` are encrypted at rest (AES-256-GCM, BYOK) and are only decrypted if the credential includes them. Successful queries and policy rejections are signed and chained into an append-only audit trail.

## Quick start with Docker

From `demo/playground` in a clean repository clone:

```bash
docker compose up --build
```

Use Docker Engine 28.3.3 or newer and Docker Compose 2.20 or newer. Older Docker Engine releases do not provide the same loopback-publishing guarantees.

Open [http://127.0.0.1:3100](http://127.0.0.1:3100). Compose builds the repository package, starts a dedicated PostgreSQL 16 database, runs the idempotent setup after PostgreSQL becomes healthy, and starts the Playground only after setup succeeds. No provider API key is required.

Once startup completes, check database readiness from a second terminal:

```bash
curl -fsS http://127.0.0.1:3100/readyz
```

The application port is published only on host loopback. PostgreSQL is not published to the host. If port 3100 is already in use, select another loopback port without changing the container:

```bash
PLAYGROUND_PORT=3110 docker compose up --build
```

Normal `stop`, `start`, and `restart` operations retain the database and generated master key in named Docker volumes. To stop the stack without deleting them:

```bash
docker compose down
```

For a full reset that removes both the Playground database and generated local key:

```bash
docker compose down --volumes
```

The next `docker compose up --build` creates a fresh database and key.

## Local demo boundaries

`alice` and `bob` are fixed local mock identities, not production authentication. A browser login creates an opaque visitor session backed by its own database, `AgentScope`, pools, simulator, and mock sessions. Agent and audit records, protected orders, and direct-SQL changes belong to that visitor database, even when two visitors choose the same mock identity. The migrated, encrypted template is shared only as the source for new clones; mock identity and UI filtering are not production tenancy boundaries.

Visitor sessions have a configured inactivity TTL and active-session cap. Shutdown closes their resources before dropping their databases. On restart, old cookies are invalid and startup cleanup attempts to remove stale Playground-owned visitor databases. This cleanup is best-effort: databases that cannot safely be dropped are reported without preventing the Playground from starting.

The Playground owns the HTTP and network boundary and validates request input. Agents++ remains responsible for validating credentials and enforcing agent ownership and query scope.

## HTTP boundary modes

The server defaults to `PLAYGROUND_HTTP_MODE=local`. Docker Compose explicitly uses this mode, so the existing loopback-only demo keeps its current behavior.

To select `PLAYGROUND_HTTP_MODE=public`, provide both settings:

```bash
PLAYGROUND_PUBLIC_ORIGIN=https://playground.example.com
PLAYGROUND_TRUSTED_PROXY_IPS=10.0.0.12,10.0.0.0/24,2001:db8::/32
```

`PLAYGROUND_PUBLIC_ORIGIN` must be one HTTPS origin without a path, query, or credentials. `PLAYGROUND_TRUSTED_PROXY_IPS` is a comma-separated list of trusted proxy networks for the immediate network peer: literal IP addresses (exact match, equivalent to `/32` or `/128`) and IPv4 or IPv6 CIDR networks. In public mode, requests must come from a peer inside one of those networks; `Host`, a supplied `Origin`, and supplied `X-Forwarded-Host` / `X-Forwarded-Proto` values must match the configured origin. Forwarded headers never make an untrusted peer trusted, and zero-width networks such as `0.0.0.0/0` or `::/0` are rejected at startup along with every malformed entry: the server refuses to serve traffic rather than trust a broader network. Public `POST /api/*` requests must include that exact `Origin`. The visitor cookie is `HttpOnly`, `SameSite=Lax`, and scoped to `/`; it is also `Secure` in public mode. `X-Forwarded-For` is used only to identify clients for session rate limiting, and only after the connection is confirmed to come from a trusted proxy.

API responses use `Cache-Control: no-store`. Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`; public mode also sends HSTS. Unexpected server and database errors return a generic response and logs contain only the error type and safe error code. Expected validation, authorization, and bounded SQL-timeout messages remain available to the demo.

`GET /healthz` reports process health without checking PostgreSQL or creating a visitor session. `GET /readyz` runs `SELECT 1` against the existing administrative pool and reports only ready/not-ready; neither probe provisions a visitor database. Readiness results, including failures, are cached in memory for two seconds per server instance, and concurrent probes share a pending check. Probe responses retain `Cache-Control: no-store`. Compose uses `/healthz` for its liveness check.

New visitor sessions are limited per client IP to 10 attempts per 60 seconds by default. Configure `PLAYGROUND_NEW_SESSION_RATE_LIMIT` and `PLAYGROUND_NEW_SESSION_RATE_WINDOW_MS` to change those positive-integer values. Valid sessions can still be reused after the new-session limit is reached. Public mode uses `X-Forwarded-For` only after the socket peer passes the trusted-proxy check; the ingress must replace or append the actual client address to that header. This application-level rate limit still depends on the ingress sanitizing forwarded headers correctly and does not replace a gateway-wide limit.

## Manual requirements

- Node.js ≥ 20.3
- PostgreSQL 16 (or Docker)
- The repository package built at `../../dist`

## Manual setup

From the repository root:

```bash
npm install
npm run build
```

From `demo/playground`, install the demo dependencies:

```bash
npm install
```

### Dedicated PostgreSQL

Start a fresh dedicated PostgreSQL container (from any directory). Host port 54322 must be free; do not reuse an unrelated database already listening there. This publishes PostgreSQL only on loopback and matches the default setup connection:

```bash
docker run --detach --name abaxx-playground-pg \
  --env POSTGRES_PASSWORD=postgres \
  --publish 127.0.0.1:54322:5432 \
  postgres:16-alpine
```

Check that PostgreSQL is accepting connections before proceeding (repeat while it is starting):

```bash
docker exec abaxx-playground-pg pg_isready -U postgres -d postgres
```

The container uses the image's default `postgres` database and administrative user. Setup and visitor-database provisioning require those administrative privileges. The Docker Engine version recommendation in Quick start also applies to this loopback publication.

### Initialize and start the Playground

From `demo/playground`, run migrations, seed the order book, encrypt the protected columns, and start the server:

```bash
npm run setup
npm start
```

Open [http://127.0.0.1:3100](http://127.0.0.1:3100). From a second terminal, check readiness with `curl -fsS http://127.0.0.1:3100/readyz`.

The `setup` and `start` scripts first validate that `node_modules/@abaxxlabs/agents` resolves to the repository root and that the required entrypoints are built.

`npm run setup` is idempotent. It defaults to `postgresql://postgres:postgres@localhost:54322/postgres`, appends the missing `DATABASE_URL` and `AGENTS_MASTER_KEY` values to `.env` without erasing its existing content (new files are created in mode 0600; do not commit them), and applies the canonical migrations from `../../migrations`; it keeps no local copy. The protected fixture must retain its eight rows; the disposable direct-SQL fixture is reset to its canonical eight rows whenever setup runs.

The setup claims the database with its own marker before creating or encrypting the business tables. If it finds `orders`, `orders_plaintext` or a canonical `agents` table without Playground tracking, it stops and demands a fresh dedicated database instead of assuming ownership or inferring previous migrations.

## External PostgreSQL with Compose

Use a dedicated database and provide a hostname reachable from the container. On Linux, `host.docker.internal` is mapped to the Docker host. The `playground` database must already exist (setup creates tables and roles, never the database). External setup currently requires a PostgreSQL superuser or an equivalent administrative provisioning account with the full privileges setup needs to create roles, set role passwords, and transfer table ownership. A database owner with `CREATEROLE` alone is not currently supported. The running Playground uses this administrative account to clone and clean up visitor databases; each visitor's data routes use the restricted `agents_playground_app` role. Setup creates the demo's `agents_playground_naive` role for that visitor's direct-SQL comparison table. Run setup first, then start the Playground without the Compose PostgreSQL dependency:

From `demo/playground`:

```bash
PLAYGROUND_DATABASE_URL=postgresql://postgres:postgres@host.docker.internal:5432/playground \
  docker compose run --build --rm --no-deps setup

PLAYGROUND_DATABASE_URL=postgresql://postgres:postgres@host.docker.internal:5432/playground \
  docker compose up --no-deps playground
```

Setup probes these privileges before making any change and fails with a clear error when they are missing.

Set `PLAYGROUND_MASTER_KEY` to an existing 64-character hex key when reconnecting to encrypted data. If omitted on a new dedicated database, setup generates and persists one in the Compose configuration volume. Setup refuses databases containing unmanaged `orders`, `orders_plaintext`, or canonical Agents++ tables.

## Docker build context verification

Compose uses the repository root as its build context. `Dockerfile.dockerignore` beside the Playground Dockerfile supplies the complete exclusion list: Docker gives it precedence over the root `.dockerignore`, rather than merging the two. It excludes environment files, installed dependencies, Git metadata, build output, generated CSS, logs, archives, and local tooling state while keeping the package sources, lockfiles, build configuration, migrations, vendored code, and Playground inputs.

From `demo/playground`, run the opt-in check with Docker Engine and Buildx available:

```bash
npm run test:docker-context
```

The check copies the actual ignore rules into a temporary fixture with the same `demo/playground/Dockerfile` path. A `FROM scratch` build exports `COPY . /context` to a temporary local directory, without pulling a base image or building the application. It checks excluded markers at the root and nested levels, retained build-input markers, and precedence over a contradictory root ignore file, then removes its temporary files. This checks Docker's filtering behavior; the full application build is covered separately by the Compose check.

See Docker's [ignore-file rules](https://docs.docker.com/build/building/context/#dockerignore-files) and [local exporter](https://docs.docker.com/build/exporters/local-tar/).

## Compose verification

The end-to-end check builds a disposable stack, verifies template and visitor seed counts, visitor-scoped direct SQL and authorized decryption, restarts the application, checks stale-cookie invalidation, graceful shutdown and closed database pools, performs a full volume reset, exercises an external PostgreSQL path without the Compose database (including a clean early failure for an unprivileged setup user), and removes its test resources:

From `demo/playground`:

```bash
npm run test:compose
```

Set `PLAYGROUND_SMOKE_BASE_URL` to a deployed HTTPS origin to run the HTTP-only remote smoke against that service instead: no local containers are started and PostgreSQL is not queried directly. The value must be a bare origin without a path, query, or credentials; an empty or invalid value fails before either smoke starts.

Each remote run opens three visitor sessions (Alice, Bob, and a second Alice for the isolation checks). The server holds a session until its inactivity TTL elapses and the HTTP surface exposes no logout, so several runs started within one TTL window can reach `PLAYGROUND_MAX_VISITOR_SESSIONS` (default 10) and receive a 503; the effective session cap and TTL depend on the deployed instance's configuration.

## Shared-row SQL isolation proof

This bounded, non-serving proof builds the canonical Playground image from the current checkout by default and reuses its native SQLite runtime proof. It does not duplicate that image packaging or runtime lifecycle implementation. The current serving path, database provisioning, SQL routes and canonical migrations remain unchanged.

From `demo/playground`, with Docker and host Node.js 22+ available:

```bash
npm run proof:sandbox-isolation
```

To reuse an already-built compatible image instead of rebuilding, run `npm run proof:sandbox-isolation -- --image <image-reference>`. The image must supply `scripts/sqlite-runtime-proof/runtime.mjs`, the real linked SDK and native SQLite under Node 22 as the non-root runtime user. An incompatible image fails the proof instead of substituting host storage. The runner records source revision/working-tree state, local lockfile hash, build selection, immutable image identity, runtime-module hash and hashes of the isolation modules mounted read-only. With `--image`, local source provenance describes the runner checkout, not a claim that the selected image was built from it.

The runner creates a fresh private PostgreSQL 16 instance with no published ports, a common encrypted fixture, and two private mutable sandboxes with identical local IDs. It exercises real protected SDK allow/deny behavior, private SQLite audit, the existing raw SQL parser, direct database hostile-SQL probes, scoped reset and raw-bytes comparison. Generated `report.json` and `report.md` are written below `test-results/sandbox-isolation-proof/`; `--output <directory>` selects another destination. The recorded run is preserved in `reports/sandbox-isolation-proof.json`.

The selected context is HMAC-signed by a separate trusted control role and bound to sandbox, backend PID, transaction ID and login role. Visitor SQL cannot read the signing key or invoke signing/reset/control functions. Role-specific non-owner/non-BYPASSRLS pools use one connection each to prove physical reuse across success, SQL/SDK rejection and transaction failure. Each executor pins its client through `BEGIN`, context installation and `COMMIT`/`ROLLBACK`, then runs `DISCARD ALL` before release; failed rollback or sanitation discards the client. Neither runtime owns these process pools.

RLS applies both `USING` and `WITH CHECK`; raw writes are column-granted without `sandbox_id`, and an immutable-owner trigger provides an additional boundary. A separate control-only, non-login/non-owner probe exercises a real rejected cross-sandbox INSERT and a successful own-sandbox INSERT without expanding visitor grants. Reset uses sandbox-scoped DELETE/reseed, never shared-table TRUNCATE. Raw-bytes reads private plaintext through the raw role and the common ciphertext through the protected role.

Limitations: the control role and server-side sandbox selection are trusted; this is not an authenticated HTTP path or a production multitenancy API. Ordinary PostgreSQL system metadata is not claimed hidden. Runtime lifecycle/audit limitations from the consumed runtime proof remain applicable, including serialized audit operations. Lease/generation fencing, routing, concurrent reset/janitor exclusion and capacity acceptance are not implemented or approved here; later fencing must compose within the pinned transaction, not rely on a pre-execution check. Any boundary bypass or failed mandatory check returns a failed gate.

Primary references: [PostgreSQL row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html) and [node-postgres transactions](https://node-postgres.com/features/transactions).

## Browser smoke tests

Start the Playground with the Docker Compose setup in Quick start and leave it running, then from `demo/playground`:

```bash
npm run test:e2e
```

## Local SQLite runtime feasibility proof

Requires Node.js 22 or newer on the host, Docker Engine, and access to the image/package registries during the build. From `demo/playground`:

```bash
npm run proof:sqlite-runtime
```

The command builds the canonical Playground image, starts a disposable PostgreSQL 16 instance on a private internal Docker network, initializes the canonical migrations and two encrypted sample rows, and runs the real SDK as the image's non-root Node 22 user. It publishes no ports and does not start the HTTP server. Its generated credentials are separate from the usual demo configuration. Normal completion, failure, SIGINT and SIGTERM remove its own containers, anonymous database volume and network; the built image remains available for inspection. A forcibly killed host organizer cannot execute cleanup.

Two visitors use independent SQLite `:memory:` stores while borrowing process-owned PostgreSQL pools (query maximum 2, raw maximum 1, connection timeout 3 seconds, statement timeout 5 seconds). The query role can read only the protected rows and encryption metadata, and the raw role only the plaintext control table. Visitor identity, signed audit and revocation operations cannot read or write the PostgreSQL control tables. The common encrypted fixture uses one generated master key with separately owned per-runtime buffers; this proves storage isolation, not distinct visitor cryptographic keys or SQL row tenancy.

The proof exercises real local DID owners, signed credentials and presentations, encrypted allowed reads, same-SQL denied/broad-credential controls, a wrong-visitor credential, revocation, independent audit storage, signature corruption and complete audit chains. It then drains and disposes A, checks that retained SQLite handles reject access, and executes another full query/audit operation through B. No external human-login flow is exercised.

The default workload is 20 warmup cycles and 200 measured cycles. Each cycle creates one fresh runtime, agent and two credentials, performs allow/deny/broad/revoke/reject operations, checks four audit signatures and the chain, and disposes the runtime using the same process pools. RSS, heap/external/ArrayBuffer memory, file descriptors, active-resource counts, pool counters and runtime accounting are sampled after warmup and every 25 measured cycles. Memory deltas and regression slopes are observations, not a capacity benchmark or a universal leak threshold.

A separate worker holds two live visitors and is terminated with SIGKILL. The host verifies exit 137 without OOM, observes PostgreSQL disconnection, and starts a new worker against the same database. The new stores must contain no previous agents, audit or revocations; fresh agents must still query successfully. Protected PostgreSQL data must remain unchanged and its identity/audit/revocation/session/context tables empty.

```bash
# Short diagnostic execution; it is not the default measured workload.
npm run proof:sqlite-runtime -- --cycles 5 --warmup 2

# Reuse an image already built by this command; rebuild after changing source.
npm run proof:sqlite-runtime -- --image <existing-image-reference> --cycles 200 --warmup 20
```

The output directory defaults to `test-results/sqlite-runtime-proof/<run-id>/`; override it with `--output <directory>`. `report.json` contains the image ID/digests, source revision/dirty state, lock checksum, actual runtime/driver versions, limits, checks, measurements, cleanup and per-criterion results. `report.md` is the readable summary. Failure, timeout, missing output, an incomplete restart or failed cleanup returns a nonzero status and cannot approve migration. Raw credential values and worker error messages are not exported. An existing-image run records the selected image separately from the host source state.

### Interpretation and required limitations

- The proof wrapper controls admission and drains tracked work. `AgentScope.close()` does not close caller-supplied storage/pools or itself guard its SQL query method; the proof explicitly characterizes retained SDK query/signer handles before closing SQLite.
- The observed caller-owned key buffers are overwritten. Opaque signers, imported-key caches, loaded column keys, immutable strings and all process-memory copies are not demonstrated erased. Hard worker termination does not run graceful cleanup or demonstrate zeroization.
- SDK `verifyRecord()` verifies the JWT signature and compares the signed payload with the supplied record's covered fields. The proof requires rejection of a record whose `rowCount` was changed without replacing its signature, also compares covered payload fields independently, and validates the complete chain. For the query/rejection records exercised here, some fields remain unsigned and chain validation cannot prove absence of deleted rows. Public DID signatures are intentionally verifiable by another visitor; store isolation is a different property.
- Queries within a runtime are serialized and their audit timestamps separated. Concurrent same-millisecond chain-head ordering is not validated by this workload.
- Session non-recovery means the restarted runtime has no old local state. It does not mean that every previously issued credential has become cryptographically invalid.

See [recorded local evidence](reports/sqlite-runtime-proof.md). The result is a feasibility assessment, not approval of migration, hostile-SQL isolation, multi-worker routing or 100/1000-user capacity.

## Worker ownership, draining and fencing proof

This bounded, non-serving proof is the initial gate for the scalability composition on top of the recorded SQLite runtime and SQL isolation proofs. It does not change the current serving path, provisioning, SQL routes or migrations, and it does not claim production migration, capacity, high availability or durable-session behavior.

From `demo/playground`, with Node.js 22+ on the host and Docker available:

```bash
npm run proof:worker-routing-fencing
```

To reuse an already-built compatible image instead of rebuilding, run `npm run proof:worker-routing-fencing -- --image <image-reference>`. The command builds the canonical Playground image, starts a fresh private PostgreSQL 16 instance and a private internal Docker network with no published ports, runs the catalog fixture, and starts two workers plus one driver. Generated `report.json` and `report.md` are written below `test-results/worker-routing-fencing-proof/`; `--output <directory>` selects another destination.

The two workers each run the real in-memory SDK runtime for their own sessions and share one PostgreSQL data plane. A catalog enforces one live session per sandbox (partial unique index), with an owner, a generation, a lease deadline and a per-sandbox advisory lock. Fenced mutations open a transaction, verify the worker's cached ownership belief against the catalog at the transaction boundary, apply the change, re-verify and commit. The public port strips internal headers; the internal port requires a per-worker HMAC, hop-limit-1, a deadline window and a catalog re-resolve of the destination.

The driver injects the faults: a dead owner (retire + janitor reap), a catalog outage (PostgreSQL stop over the mounted Docker socket), stale-generation and in-flight mutations, a cross-worker transfer, and forged internal hops. It asserts the routing matrix, drain/retire admission, fencing and stale-owner safety, and emits exactly one result record. The in-proof HMAC is test scaffolding, not production workload identity: the recorded report states the mTLS/SPIFFE requirement and does not claim gateway-only header policy is sufficient.

See [recorded local evidence](reports/worker-routing-fencing-proof.md). The recorded run passes all 147 driver checks and both worker evidence contracts, and cites the merged 887 SQLite runtime and 888 SQL isolation reports as the prerequisite inputs to the combined initial gate.

## Frontend styles

Tailwind CSS 4 scans the utility classes in `public/index.html` and the JavaScript renderers to generate `public/styles.css`. The single CSS entry, `styles/tailwind.css`, contains the design tokens, the existing 520/800px breakpoints, and the minimal reset. Preflight is omitted to preserve browser defaults. The generated CSS is ignored by Git; `npm start` and `npm test` rebuild it automatically, and Docker compiles it before pruning development dependencies.

For CSS changes while the local server is running, use a second terminal in `demo/playground`:

```bash
npm run dev:css
```

Use `npm run build:css` for a one-off production CSS build.

## What to try in the UI

1. **Authenticate** as alice (head trader, unrestricted ceiling) or bob (junior, ceiling `[instrument, side, quantity, status]` assigned server-side, as it would come from IdP groups in production).
2. **Create agent**: it receives a `did:key:…` DID and a private key encrypted with the master key.
3. **Issue credential** checking columns. As **bob**, checking `price` returns `ScopeExceedsCeilingError`.
4. **Supervisor→worker delegation**: issue a credential as alice and delegate to the worker a subset that is equal to or more restricted than it. The UI selects only the plain columns by default; the chain cannot widen the scope.
5. **SQL console**: `SELECT *`, `DELETE` and hidden mutations in CTEs are rejected before execution.
6. **Audit trail**: queries and policy rejections are signed and chained to the previous record. The verify button checks the hash links; it does not verify each record's signatures.

## Structure

```text
scripts/check-linked-agents-build.mjs  # linked package preflight
scripts/check-docker-context.mjs       # opt-in Docker context filtering check
scripts/setup-db.mjs                   # canonical migrations + seed + encryption
scripts/compose-smoke.mjs              # disposable Compose end-to-end check
scripts/smoke-dispatch.mjs             # test:compose entry; local Compose or deployed origin
scripts/remote-smoke.mjs               # HTTP-only smoke for a deployed origin
scripts/remote-smoke-client.mjs        # HTTP client shared by the remote smoke
scripts/sqlite-runtime-proof.mjs       # local real-image SQLite feasibility organizer
scripts/sqlite-runtime-proof/          # fixture, SDK scenarios, lifecycle and reporting
scripts/worker-routing-fencing-proof.mjs # local real-image routing/drain/fencing organizer
scripts/worker-routing-fencing-proof/    # catalog, fenced executor, router, driver
src/server.mjs                         # server bootstrap and lifecycle
src/visitor-http.mjs                   # node:http API and visitor session routing
src/routes-sim.mjs                     # simulator endpoints
public/                                # framework-free frontend
styles/tailwind.css                     # theme, breakpoints, and minimal reset
test/                                  # playground integration contracts
e2e/                                   # browser smoke tests (Playwright)
```
