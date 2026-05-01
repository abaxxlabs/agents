# Agents++

Identity and access control for AI agents on PostgreSQL.

Every agent gets a verifiable identity (DID), scoped credentials (VCs), and column-level encryption. Two agents querying the same table get different cleartext based on their credentials.

Current public release: npm package `@abaxxlabs/agents@0.11.3` (release label `0.11.3.0`).

## Get started

```bash
npx @abaxxlabs/create-agents my-app
cd my-app
```

You need PostgreSQL running first:

```bash
supabase start                    # if you have Supabase CLI + Docker
# or
docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine
```

Then:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The app runs in dev mode (mock auth) by default. Three agents with different column scopes query the same order book data.

## v0.11 Migration — subpath exports

v0.11 splits the package into subpath exports so non-SQL consumers (MongoDB, GraphQL, MySQL) can use identity and credentials without pulling in `pg`.

| Subpath | What it provides | Peer dependency timing |
|---------|-----------------|------------------------|
| `@abaxxlabs/agents` | AgentIdentity, auth, credentials, storage, crypto | No SQL peers |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management | Requires `pg@8.20.0` + `libpg-query@17.7.3` |
| `@abaxxlabs/agents/mcp` | MCP server factory and CLI starter | Imports without SQL peers; SQL-backed startup/tools require them |
| `@abaxxlabs/agents/storage` | Storage backend composition utilities | No SQL peers |
| `@abaxxlabs/agents/sqlite` | SQLite storage backend (bun:sqlite / better-sqlite3) | Node requires `better-sqlite3@11.10.0`; Bun has built-in SQLite |
| `@abaxxlabs/agents/bootstrap` | Master key resolution from env | No SQL peers |

```typescript
// Before (v0.10):
import { AgentScope } from '@abaxxlabs/agents';

// After (v0.11):
import { AgentScope } from '@abaxxlabs/agents/sql';
import { AgentIdentity } from '@abaxxlabs/agents';
```

Importing `AgentScope` from the root entry now throws a descriptive error at runtime (and fails type-check at build time) directing you to `@abaxxlabs/agents/sql`.

The six subpaths above are the supported public package contract for `0.11.3` (release label `0.11.3.0`).
CI snapshots their exported names and fails on accidental public API drift.

Full migration guide: [`docs/migration-v0.11.md`](docs/migration-v0.11.md)

## Platform identity architecture

`@abaxxlabs/agents` ships as a standalone package — `did:key` agent identities, hand-rolled JWT signing on `node:crypto`, in-memory or Postgres storage, no external infrastructure required. It does **not** require the platform identity stack; the package operates without it.

The platform-backed deployment path connects to AbaxxOne services: the migration provisions a fresh `did:dht` identity from AbaxxOne's custodial keystore with a 7-day grace period. The migration executor (`src/migration.ts`) wires into the public API for platform-enabled deployments. Customers inject an MCP-backed platform identity handle at `AgentScope.create(config, { masterKey, sdk })` to enable did:dht resolution, AbaxxOne organizational identity, hosted status lists, and DWN persistence plus agent-to-agent comms. Use `connectIdSdkMcp()` from `@abaxxlabs/agents/id-sdk-mcp`; the MCP server keeps platform session state and signing authority outside the core package.

```ts
import { connectIdSdkMcp } from '@abaxxlabs/agents/id-sdk-mcp';
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();
const sdk = await connectIdSdkMcp({
  connect: { didMethod: 'dht', sync: '30s' },
});

const scope = await AgentScope.create(config, { masterKey, sdk });
```

`@abaxxlabs/agents` and the platform identity stack are **peer implementations** by deliberate design — both implement W3C DID/VC/VP standards. Credentials issued by either tier are mutually verifiable by any compliant verifier in the ecosystem.

For ecosystem partners and engineers evaluating agents++ for adoption: the standalone package is genuinely usable by itself (see "Get started" above). The platform-backed value lives in AbaxxOne services (DHT network, custodial keystore, trust routing), not in software locks on this codebase. Any verifier in the ecosystem can accept credentials issued by either deployment model, so building on the standalone package today does not strand customers if they later connect AbaxxOne services.

## How it works

```
Human authenticates (OIDC) --> issues credential to agent --> agent queries
                                                                 |
                                                          ScopeEngine verifies
                                                          credential, decrypts
                                                          only authorized columns
                                                                 |
                                                          Audit record signed
                                                          by agent's DID
```

1. **Human authenticates** via Google, Microsoft, AbaxxOne, or any OIDC provider
2. **Human creates agent** with a DID (did:key, Ed25519)
3. **Human issues credential** specifying which columns the agent can access
4. **Agent queries** through the ScopeEngine
5. **ScopeEngine verifies** the credential (signature, expiry, scope, owner binding)
6. **ScopeEngine enforces** the projection boundary (rejects queries referencing out-of-scope encrypted columns), then decrypts authorized columns (AES-256-GCM)
7. **Audit record** is cryptographically signed and appended to a tamper-proof hash chain

## SDK usage

All SQL examples pass a `MasterKey` through `AgentScope.create(config, injections)`. `resolveMasterKeyFromEnv()` is the packaged bootstrap helper for env-based deployments; KMS, HSM, or vault users can pass their own branded key instead.

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();

// Connect to PostgreSQL with encryption config
const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL },
    encryption: { columns: ['order_book.quantity', 'order_book.price', 'order_book.counterparty'] },
    audit: { enabled: true },
  },
  { masterKey },
);

// Authenticate (mock in dev, real OIDC in production)
const session = await scope.authenticate({ mockHumanDid: 'Trader-1' });

// Create an agent under the authenticated human
const agent = await scope.createAgent({
  name: 'market-agent',
  ownerDid: session.humanDid,
});

// Issue a scoped credential
const credential = await session.issueCredential({
  agent: agent.did,
  columns: ['order_book.instrument', 'order_book.quantity', 'order_book.price'],
  actions: ['read'],
  expiresIn: '4h',
});

// Query -- only authorized columns are decrypted
const result = await scope.query({
  agent: agent.did,
  credential,
  table: 'order_book',
  sql: 'SELECT instrument, quantity, price FROM order_book',
});
// result.rows: instrument, quantity, price in cleartext
// Querying 'counterparty' (encrypted, out of scope) would throw ScopeViolationError
```

## Agent-to-agent delegation

Supervisor agents can delegate a subset of their scope to worker agents:

```typescript
const workerCred = scope.delegateCredential(supervisor.did, supervisorCred, {
  targetAgent: worker.did,
  columns: ['order_book.instrument', 'order_book.quantity'],  // must be subset of supervisor's scope
  actions: ['read'],
  expiresIn: '1h',                              // capped at supervisor's remaining TTL
});

const result = await scope.query({
  agent: worker.did,
  credential: workerCred,
  table: 'order_book',
  sql: 'SELECT instrument, quantity FROM order_book',
});
```

Constraints enforced:
- Delegated columns must be a subset of the source credential
- Delegated actions must be a subset of the source credential
- TTL cannot exceed the source credential's remaining lifetime

## Authentication

Three paths, depending on your deployment:

### Dev/test mode (no OIDC required)

```typescript
// NODE_ENV must be 'development' or 'test'
const session = await scope.authenticate({ mockHumanDid: 'Trader-1' });
```

### Web app with real OIDC (Google, Microsoft, AbaxxOne)

Your web app handles the OAuth redirect flow, then passes the identity to the SDK:

```typescript
const session = await scope.authenticate({
  oidcIdentity: {
    humanDid: derivedDid,       // SDK derives this from (issuer, sub)
    issuer: 'https://accounts.google.com',
    sub: '104123456789',
    email: 'trader@firm.com',
  },
});
```

### AbaxxOne (enterprise, real DIDs)

```typescript
const scope = await AgentScope.create(
  {
    database: { connectionString: DB_URL },
    abaxxOne: { tenantUrl: 'https://auth.abaxxone.com', clientId: 'YOUR_CLIENT_ID' },
  },
  { masterKey },
);
```

AbaxxOne provides real HSM-backed DIDs (did:dht), institutional trust anchors, and governed revocation. Generic OIDC providers produce deterministic but self-asserted DIDs (did:key) derived from the OIDC sub claim.

### Parent Instance (AbaxxOne Enterprise)

When running under an AbaxxOne parent instance, agent credentials are issued by the organization's DID rather than the human's self-issued DID. This gives agents institutional trust — any verifier that trusts the org can verify the agent's credential without contacting the issuing human.

```typescript
import { AbaxxOneOidcProvider } from '@abaxxlabs/agents';

// 1. Configure the AbaxxOne provider
const provider = new AbaxxOneOidcProvider({
  tenantUrl: 'https://auth.abaxxone.com',
  clientId: 'YOUR_CLIENT_ID',
});

// 2. Authenticate the human via OIDC (produces identity + access token)
const { identity, accessToken } = await provider.loginProgrammatic();

// 3. Request a parent-issued credential for the agent
const { jwt, issuerDid } = await provider.requestAgentCredential(
  accessToken,
  agent.did,
  { columns: ['order_book.quantity', 'order_book.price'], actions: ['read'], expiresIn: '4h' },
);

// 4. Add the parent's DID as a trust anchor
await trustAnchorStore.addParentTrust(issuerDid);

// issuerDid is the org's DID (did:dht:...), not the human's self-issued DID
```

Key differences from free tier:
- **Credential issuer**: org DID (did:dht), not human DID (did:key)
- **Trust anchors**: parent anchors are ephemeral — re-derived from credential chain each session, never persisted to keystore
- **Audit records**: V3 format includes `orgId` for org-scoped audit trails
- **Scope ceiling**: agent capabilities are bounded by what the parent authorized via `parentScopeCeiling` in AgentVerifier

### Migrating to platform-backed identity

Upgrading from self-issued credentials to AbaxxOne parent-issued credentials requires three changes:

**Step 1: Configure the AbaxxOne provider**

Replace mock or generic OIDC authentication with AbaxxOneOidcProvider:

```typescript
// Before (free tier)
const session = await scope.authenticate({ mockHumanDid: 'Trader' });

// After (platform-backed identity)
const provider = new AbaxxOneOidcProvider({
  tenantUrl: 'https://auth.abaxxone.com',
  clientId: process.env.ABAXX_CLIENT_ID!,
});
```

**Step 2: Use parent-issued credentials**

The session's `issueCredential()` method automatically attempts the parent path first and falls back to local signing:

```typescript
// Authenticate and get the access token (from Step 1 provider)
const { identity, accessToken } = await provider.loginProgrammatic();
const { jwt, issuerDid: parentIssuerDid } = await provider.requestAgentCredential(
  accessToken, agent.did, { columns, actions, expiresIn: '4h' },
);

// createSessionFromDid() accepts parentConfig —
// issueCredential() tries parent-issued → SDK → local in order
const session = createSessionFromDid(humanDid, email, verifier, sdk, oidcConfig, undefined, ceiling, {
  provider,
  accessToken,
  issuerDid: parentIssuerDid,
  credentialExp: parentExp,
});

// This now issues via parent when available, falls back to local
const cred = await session.issueCredential({ agent: agent.did, columns, actions, expiresIn: '4h' });
```

**Step 3: Add orgId to audit records**

Pass `orgId` when logging audit entries to enable org-scoped filtering:

```typescript
auditLogger.log({
  agentDid: agent.did,
  action: 'scope:read',
  table: 'order_book',
  orgId: 'your-org-id',  // enables V3 audit records with org filtering
});
```

All existing standalone code continues to work — the migration is additive. Markers in the codebase (`AGENTS_UPGRADE`) indicate each point where platform-backed behavior diverges.

## MCP server

AI agents (Claude, GPT, etc.) can use Agents++ through the Model Context Protocol. MCP is a supported `0.11.3` release surface, not demo-only code: the package ships the `@abaxxlabs/agents/mcp` server factory and the `agents mcp` CLI entrypoint, while `@abaxxlabs/agents/id-sdk-mcp` provides the platform identity adapter for deployments that keep AbaxxOne session state behind an MCP process boundary.

`@abaxxlabs/agents/mcp` itself imports in a fresh tarball consumer without
manually adding SQL peer dependencies. Starting the SQL-backed MCP server or
using the query tool requires the documented peer set:
`pg@8.20.0 libpg-query@17.7.3`.

```bash
# stdio mode (Claude Desktop, Claude Code)
agents mcp --db postgresql://localhost/mydb --mock "Trader-1"

# HTTPS mode (remote clients)
agents mcp --db postgresql://localhost/mydb --transport http --tls-cert cert.pem --tls-key key.pem
```

### Claude Desktop

```json
{
  "mcpServers": {
    "agents": {
      "command": "npx",
      "args": ["@abaxxlabs/agents", "mcp", "--db", "postgresql://localhost/mydb", "--mock", "Trader-1"]
    }
  }
}
```

### stdio vs HTTP — trust boundary

`stdio` mode runs the MCP server as a child process of the host application (Claude Desktop, Claude Code). It shares the host's process environment. This is appropriate for developer tools where a human is directly supervising the session.

For autonomous AI agents making production queries, use HTTP/HTTPS transport:

```bash
agents mcp --db postgresql://localhost/mydb \
  --transport http \
  --tls-cert cert.pem \
  --tls-key key.pem \
  --port 8443
```

In HTTP mode, the MCP server is a separate process. The master key and database credentials live only in that process's environment. The agent calls it over the network and never has access to either. HTTP transport without TLS is rejected unless `NODE_ENV=development` or `NODE_ENV=test`.

See [Process isolation](#process-isolation) below for why this matters.

### MCP tools

| Tool | Description |
|------|-------------|
| `query` | Scoped SQL query with credential authorization |
| `create-agent` | Create agent identity (DID + keypair) |
| `issue-credential` | Issue scoped Verifiable Credential JWT |
| `revoke-credential` | Revoke a credential |
| `verify-audit` | Verify audit record signature |
| `export-audit` | Export filtered audit records |
| `list-agents` | List registered agents |
| `verify-chain` | Verify audit hash chain integrity |

## REST API

For non-Node.js consumers (Python, Go, curl), run agents as a standalone HTTP server:

```bash
agents serve --db postgresql://localhost/mydb --port 3100
```

CLI commands reject `--master-key <hex>` because argv can leak through process
listings and shell history. Set `AGENTS_MASTER_KEY` in the process environment
or pipe a key file with `--master-key-stdin`.

Swagger UI at [http://localhost:3100/docs](http://localhost:3100/docs). OpenAPI spec at `/openapi.json`.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/session` | Authenticate (mock or OIDC identity) |
| GET | `/agents` | List agents owned by the authenticated session |
| POST | `/agents` | Create agent |
| POST | `/agents/:did/delegate` | Delegate credential to worker agent |
| GET | `/credentials` | List credential metadata visible to the session |
| POST | `/credentials` | Issue scoped credential |
| DELETE | `/credentials/:id` | Revoke credential |
| POST | `/query` | Scoped query (credential determines column access) |
| GET | `/audit` | Export audit trail |
| POST | `/audit/verify` | Verify an audit record signature |
| POST | `/audit/verify-chain` | Verify audit hash-chain integrity |
| GET | `/whoami` | Return the server verifier DID |
| GET | `/discover` | Return current trust-topology metadata |
| POST | `/challenge` | Issue a short-lived VP challenge |
| POST | `/sign` | Stubbed server-signing endpoint; returns 501 until ServerIdentity signing is wired |
| GET | `/mcp/sse` | Open an authenticated MCP-over-SSE stream when MCP is enabled |
| POST | `/mcp/messages` | Send MCP messages to an active SSE transport |
| DELETE | `/admin/sessions/:token` | Revoke a REST session token with `x-admin-key` |
| GET | `/livez` | Process liveness; does not check dependencies |
| GET | `/readyz` | Dependency readiness with safe dependency-class reporting |
| GET | `/health` | Server status |

### Example (curl)

```bash
# Create a session
SESSION=$(curl -s -X POST http://localhost:3100/auth/session \
  -H "Content-Type: application/json" \
  -d '{"mockHumanDid": "Trader-1"}' | jq -r .sessionId)

# Create an agent
AGENT_DID=$(curl -s -X POST http://localhost:3100/agents \
  -H "Content-Type: application/json" -H "x-session: $SESSION" \
  -d '{"name": "market-agent"}' | jq -r .did)

# Issue a credential
CRED=$(curl -s -X POST http://localhost:3100/credentials \
  -H "Content-Type: application/json" -H "x-session: $SESSION" \
  -d "{\"agent\": \"$AGENT_DID\", \"columns\": [\"order_book.instrument\", \"order_book.quantity\"], \"actions\": [\"read\"], \"expiresIn\": \"4h\"}" | jq -r .credential)

# Query with scoped access
curl -s -X POST http://localhost:3100/query \
  -H "Content-Type: application/json" \
  -d "{\"agent\": \"$AGENT_DID\", \"credential\": \"$CRED\", \"table\": \"order_book\", \"sql\": \"SELECT instrument, quantity FROM order_book\"}"
```

## Production deployment

### Process isolation

The ScopeEngine and column encryption are software-level controls. They work correctly when the code calling them is trustworthy. A compromised or prompt-injected AI agent running in the same process as the library has access to everything that process can reach — environment variables, imported modules, database connections — and can bypass the ScopeEngine entirely without triggering any library-level check.

**Do not embed this library directly in your agent process for production use.** Instead, run the MCP server or REST API server as a separate process. The agent communicates with it over HTTP/HTTPS; the master key and database credentials never enter the agent's process.

```
Agent process                        Agents++ process
(no DB credentials,             ┌──► MCP server (HTTP/HTTPS, TLS)
 no master key)  ───REST/MCP───►│    or REST API server
                                 └──► pg.Pool ──► PostgreSQL
                                      master key (env var here only)
```

The NemoClaw reference implementation (`demo/nemoclaw/`) demonstrates this in practice. The agent runs inside an OpenShell sandbox (Landlock + seccomp). The sandbox network policy (`demo/nemoclaw/sandbox-policy.yaml`) explicitly allows outbound connections to the bridge API on port 3100 but has no rule permitting port 5432 — the agent cannot reach PostgreSQL directly. The master key is set only in the bridge server's environment on the host.

### Persistent server identity

By default, AgentScope generates an ephemeral DID on each startup. For production, pass a persistent identity so VPs and credentials remain valid across restarts:

```typescript
import { initializeServerIdentity } from '@abaxxlabs/agents';

const serverIdentity = await initializeServerIdentity(keystore, verifier);

const scope = await AgentScope.create(config, {
  masterKey,
  serverIdentity: { did: serverIdentity.did, publicKey: serverIdentity.publicKey },
});
// scope.verifierDid is now stable across restarts
```

### Shared connection pool

For multi-tenant orchestrators running many AgentScope instances, share a single pg.Pool:

```typescript
import pg from 'pg';

const pool = new pg.Pool({ connectionString: DB_URL, max: 50 });

const scopeA = await AgentScope.create(configA, { masterKey, pool });
const scopeB = await AgentScope.create(configB, { masterKey, pool });
// Both share the same connection pool
```

### Local revocation (without AbaxxOne SDK)

```typescript
// Revoke a credential by its JTI (credential ID)
await session.revokeCredential(credentialJti);
// Subsequent queries with this credential will be rejected
```

For persistent revocation across restarts, inject a durable storage backend such as the Postgres-backed default. Platform-backed deployments can also notify AbaxxOne StatusList2021 through the injected SDK.

## Architecture

```
+-------------------------------------+
|        YOUR AI AGENT                 |
|    (separate process)                |
+------------------+------------------+
                   |  HTTP/HTTPS (MCP or REST)
                   v
+------------------+------------------+
|     AGENTS++ SERVER PROCESS          |
|   (MCP server or REST API server)    |
|                                      |
|  VcVerifier --> ScopeEngine -->      |
|  Column Encryption --> AuditLogger   |
+------------------+------------------+
                   |  Standard SQL
                   v
+------------------+------------------+
|           POSTGRESQL                 |
|  Encrypted columns (AES-256-GCM)    |
|  Append-only audit trail             |
+-------------------------------------+
```

Master key and database credentials live only in the Agents++ server process. See [Process isolation](#process-isolation) for why this boundary matters.

### Security model

- **Ed25519 only** -- no algorithm agility. All DIDs use did:key with Ed25519.
- **PKCE S256** on all OIDC flows. SSRF guards on discovered endpoints (HTTPS required in production).
- **Column encryption** -- AES-256-GCM per column, keys wrapped with a master key. Key rotation: `rotateColumnKey()` re-encrypts all rows and swaps the wrapped key atomically. `rewrapColumnKey()` migrates the wrapped key to a new master key without touching row data. Both operations are transactional (all-or-nothing) and emit audit entries. `registerColumn()` now throws on re-registration — use the rotation primitives to change key material.
- **Master key handling (BYOK)** -- the master key is consumer-supplied via `injections.masterKey` on `AgentScope.create`. The library never reads `process.env.AGENTS_MASTER_KEY`; consumers source the key explicitly (env, HSM, KMS, vault). Defence-in-depth on the in-memory copy:
  - **Compile-time:** the `MasterKey` brand on `src/crypto/master-key.ts` blocks the buffer from leaking into Buffer-typed sinks. Construct via `asMasterKey(buf)`.
  - **Runtime serialisation:** `AgentScope` defines `toJSON()` and `[util.inspect.custom]` so `console.log(scope)` and `JSON.stringify(scope)` emit `masterKey: '[REDACTED 32 bytes]'`, never raw bytes.
  - **Lifecycle:** `AgentScope.close()` calls `masterKey.fill(0)` after teardown. **This is best-effort.** V8 is a moving garbage collector — earlier copies of the buffer's bytes may exist in the heap from prior compaction passes and are not reachable from JS to overwrite. `fill(0)` zeroes the *primary copy* held by AgentScope, which (a) bounds the secret's lifetime to the AgentScope lifetime and (b) zeroises any heap snapshot or core dump captured *after* `close()` returns. For hard, GC-independent guarantees, hold the key in an HSM/KMS-backed sealed buffer and pass a handle through `injections.masterKey` rather than a raw Buffer; the BYOK boundary makes that swap mechanical.
  - **Wrong-key boots fail loud.** Previously, `loadColumnKeys` and `restoreAgents` swallowed AES-GCM auth-tag failures and warned per-row, letting the boot succeed against rows the master key could not decrypt. That posture made dev-time key drift cheap, but it became a deployment-error class under BYOK: wrong key in, no audible signal out, encrypted columns silently rendering as `[ENCRYPTED]` placeholders to downstream callers. Now: if persisted column keys (or persisted agent private keys) exist in the database but cannot be decrypted with the supplied master key, `AgentScope.create` throws `MasterKeyMismatchError` with a precise message ("Column keys exist but cannot be decrypted with the provided master key. Wrong key or corrupted data."). Legitimate pre-migration boots — where the underlying tables don't exist yet — are distinguished structurally and continue to succeed with an empty key map. To rotate the master key against an existing database, use `rewrapColumnKey()` *before* swapping the key in your bootstrap; see [`docs/migration-byok.md`](docs/migration-byok.md) for the full quiesce + verify + cutover protocol, and [`docs/support-runbook-v0.9.10.0.md`](docs/support-runbook-v0.9.10.0.md) for post-upgrade diagnostics.
- **Audit trail** -- append-only with PostgreSQL triggers blocking UPDATE/DELETE. Each record is Ed25519-signed and hash-chained.
- **VP audience binding** -- credentials can be bound to a specific server's verifierDid, preventing replay across servers.
- **Owner binding** -- the ScopeEngine verifies that credential issuers are the registered owners of the agent (persisted in database, survives restarts).
- **Identity migration** -- when a user upgrades from did:key (free tier) to did:dht (AbaxxOne), an IdentityMigrationCredential triggers an atomic ownership transfer. A DID alias registry provides a grace period where both old and new DIDs are accepted in ownership checks, delegation chains, and audit queries. Migration events are recorded in the audit trail.
- **Mock auth gated** -- `mockHumanDid` only works when `NODE_ENV=development` or `NODE_ENV=test`.

### Key derivation (generic OIDC)

Generic OIDC providers produce a deterministic did:key from `sha256(issuerUrl + '\x00' + sub)`. The key is always recoverable: log in with the same OIDC account, get the same keypair, access your encrypted columns. You cannot lock yourself out of a database you encrypted with the free tier.

The tradeoff: anyone who knows the issuer URL and the user's OIDC sub claim can derive the same DID and private key. The free tier trades key confidentiality for zero-infrastructure setup and guaranteed recoverability. For key confidentiality, use AbaxxOne.

## Demos

### Showcase (7-beat presenter walkthrough)

```bash
npm install
npm run build
supabase start
cd demo/showcase
npm install
npm run dev
```

Step-by-step walkthrough: identity, scoping, pipeline verification, audit trail, attack simulation, cross-org verification. Capital markets scenario with IMF citations. Uses the shared Supabase instance (`supabase start` from the repo root), the `order_book` table, and the shared `agents` infrastructure tables.

Cold-state launch verification lives in [`demo/launch-checklist.md`](demo/launch-checklist.md). After the Showcase server is running, `cd demo/showcase && npm run smoke:launch` drives the approved launch beats through the API. Add `-- --include-extended` to include endpoint-only revocation and wrong-key checks; their UI panels are tracked separately.

## Development

```bash
npm install
npm test              # default unit/integration gate
npm run build         # TypeScript --> dist/
npm run typecheck     # Type checking only
```

## Project structure

```
src/
  index.ts              # SQL-free root public API
  sql/                  # AgentScope, ScopeEngine, and SQL column-key APIs
  types.ts              # Root public types
  auth/                 # OIDC providers, agent identity, credential issuance
  vc-verifier.ts        # Credential verification pipeline
  column-encryption.ts  # AES-256-GCM column encryption
  audit-logger.ts       # Append-only audit trail
  did-alias.ts          # DID alias registry for migration grace period
  migration.ts          # Identity migration executor (did:key → did:dht)
  identity/             # Server identity, binding credentials, trust anchors
  capability/           # Action-based capability authorization
  mcp/                  # MCP server (tools + resources)
  storage/              # StorageBackend (identity-gated persistence)
  cli/                  # CLI tool

demo/
  showcase/             # 7-beat presenter walkthrough (capital markets)

packages/
  create-agents/      # npx @abaxxlabs/create-agents scaffolder
```

## Library / SDK boundaries log

A log of decisions about what stays in the core library vs. what's consumer territory. Each entry captures the shape at the release boundary so future agents can reason about drift.

- **v0.9.8.0:** Session envelopes are a public, stable contract in core. `ISessionStore` is the 5th sub-store under `StorageBackend`. Three adapters ship: memory (default), Postgres (multi-instance + 10s cache), SQLite (Chief/local). Non-default adapters (Redis, DynamoDB, sticky-sessions-with-local-cache) are consumer territory. The library holds no opinion on which store a consumer picks — it guarantees one write path and one read path through whichever is injected. Library `src/auth/` factories remain stateless — session closures are instance-local by design.
- **v0.9.6.0:** Revocation state moved out of VcVerifier's process-local Set into `IRevocationStore` as the 4th sub-store. Postgres (durable, cross-instance coherent) + SQLite (Chief) + in-memory default.
- **v0.9.5.0:** Audit chain-head read serialized via DB-level locks (`pg_advisory_xact_lock` / `BEGIN IMMEDIATE`). Library-level change, no new public surface.
- **v0.9.4.0:** Scope ceiling + policy-guard hardening. Library enforces; server product signals.

## License

MIT
