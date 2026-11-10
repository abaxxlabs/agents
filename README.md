> [!NOTE]
> **Public mirror:** This repository is maintained through a private development process. Reviewed updates are published here by the maintainers. Public issues and pull requests are welcome.

<h1 align="center">Agents++</h1>
<p align="center"><strong>Identity, authorization, and proof for AI agents.</strong></p>
<p align="center">
  Your agent should be able to answer three questions at every interaction:<br/>
  <em>Who is it? Who authorized it? What can it see?</em><br/>
  Agents++ makes the answers cryptographic.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@abaxxlabs/agents"><img src="https://img.shields.io/npm/v/@abaxxlabs/agents?style=flat-square" alt="npm version" /></a>
  <a href="https://github.com/abaxxlabs/agents/actions"><img src="https://img.shields.io/github/actions/workflow/status/abaxxlabs/agents/ci.yml?style=flat-square" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="#the-problem">Why</a> &bull;
  <a href="#what-this-looks-like">Experience</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#playground">Playground</a> &bull;
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#mcp">MCP</a> &bull;
  <a href="#security-model">Security</a> &bull;
  <a href="https://abaxxtech.github.io/agents/documentation/">Docs</a> &bull;
  <a href="#free-tier-vs-abaxxone">Free vs AbaxxOne</a>
</p>

---

## The problem

Any credential an agent can use, a compromised agent can exfiltrate. API keys don't know who they belong to. OAuth tokens carry no delegation provenance. When an agent is breached, there's no way to tell which human authorized it, what it was supposed to access, or whether it stayed in bounds. You find out from the incident report.

These aren't edge cases. They're what happens when you build agentic systems without an identity and authorization layer. Agent runtimes solve execution -- they tell the model what tools to call. Nobody answers the harder question: *is this agent who it claims to be, acting on whose authority, with what specific permissions?* And nobody can prove it to someone outside the org.

Agents++ is the missing layer. It gives every agent a cryptographic identity (a DID), binds that identity to the human who authorized it through a verifiable credential, enforces scope at the query layer, and writes a tamper-evident audit trail. The true bottleneck holding back institutional adoption isn't better tool-calling -- it's identity verification, authorization provenance, and the cryptographic binding of human intent to machine execution.

## What this looks like

Your trading agent needs to query the order book. Without Agents++, you hand it a database connection and hope your permission checks hold:

```
Agent: "SELECT instrument, price, quantity, counterparty FROM orders"
App:   checks some boolean → allows it
DB:    returns everything
You:   trust the agent didn't go off-script
```

No proof the agent was authorized. No proof it stayed in scope. No audit trail a third party could verify.

With Agents++, a human authenticates and issues a credential that says exactly what the agent can see. The agent presents that credential when it queries. The ScopeEngine verifies the credential and its delegation chain at the query boundary:

```
Human:       authenticates via OIDC, creates agent, issues credential
             → "this agent can see orders.instrument and orders.quantity, expires in 4h"

Agent:       presents credential to ScopeEngine
ScopeEngine: ✓ credential signature, expiry, and revocation are valid
             ✓ issuer-subject-owner bindings hold (delegation chain included)
             ✓ requested columns are within scope
             ✓ SQL doesn't touch unauthorized tables
             → executes query, decrypts only authorized columns
             → signs and appends audit record

Result:      instrument | quantity
             AAPL       | 500
             TSLA       | 200

             (price and counterparty: encrypted at rest, never decrypted,
              query would have been rejected before reaching the database)
```

The credential is the authorization. The ScopeEngine is the enforcer. The audit trail is the proof.

## How it works

1. A **human authenticates** (OIDC in production, mock in dev).
2. They **create an agent** -- the agent gets a freshly generated Ed25519 keypair and DID.
3. They **issue a credential** that says exactly what the agent can see: which columns, which actions, for how long. Issuance enforces the bounds -- the credential can only ever be as narrow as what the issuer holds.
4. The agent **presents that credential** when it queries.
5. The **ScopeEngine** re-verifies the credential and its delegation chain at the query boundary (signatures, revocation, delegation-depth ceiling, issuer-subject-owner bindings), parses the SQL, rejects anything out of scope, decrypts only authorized columns, and signs an audit record. It does not re-run the issuance-time subset and TTL math -- those bounds were enforced when the credential was issued.
6. When audit is enabled, successful scoped queries are **Ed25519-signed and hash-chained** into a tamper-evident audit trail. Rejections without an available agent signer may be recorded as unsigned.

Delegation works the same way down. A supervisor agent can delegate a strict subset of its scope to a worker -- fewer columns, fewer actions, shorter TTL. The narrowing (subset, TTL, delegation depth) is enforced at issuance time: the delegated credential cannot exceed the source credential, and the depth ceiling is embedded in the root credential. At query time the ScopeEngine verifies the chain's signatures, revocation status, depth ceiling, and issuer-subject-owner bindings; it does not re-derive the subset or TTL narrowing.

## Install

```bash
npm install @abaxxlabs/agents pg@8.20.0 libpg-query@17.7.3
```

## Playground

A self-service order-book demo of Agents++: agent identity, column-scoped SQL, supervisor-to-worker delegation, columns encrypted at rest, and a signed, hash-chained audit trail. It runs entirely on your machine in Docker and needs no provider API key.

Prerequisites: Docker Engine 28.3.3 or newer and Docker Compose 2.20 or newer.

From `demo/playground` in a clean checkout:

```bash
docker compose up --build
```

Open [http://127.0.0.1:3100](http://127.0.0.1:3100). Compose builds the repository package, starts a dedicated PostgreSQL 16 database, runs the idempotent setup after PostgreSQL is healthy, and starts the Playground only after setup succeeds. From a second terminal, confirm readiness:

```bash
curl -fsS http://127.0.0.1:3100/readyz
```

If port 3100 is already in use, select another loopback port without changing the container:

```bash
PLAYGROUND_PORT=3110 docker compose up --build
```

Stop the stack and keep its data with `docker compose down`; remove the database and generated key with `docker compose down --volumes`. See the [Playground guide](docs/guides/playground.md) for what to try in the UI and the [full reference](demo/playground/README.md) for manual and external-PostgreSQL setups.

## Quick start

Prefer to start from zero? Run the [Playground](#playground): it builds the database, applies migrations, and seeds the order book in Docker with no provider key. This SDK-direct example embeds the library in your own application instead.

The example assumes that the Agents++ PostgreSQL migrations and the `orders` table are already prepared, `orders.price` is registered for encryption, and `NODE_ENV=development` is set for the mock identity path. See the [complete SDK-direct quick start](https://abaxxtech.github.io/agents/documentation/guides/quick-start) for database preparation.

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';
import { asMasterKey, createPresentation } from '@abaxxlabs/agents';

const masterKey = asMasterKey(Buffer.from(process.env.AGENTS_MASTER_KEY!, 'hex'));
const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL! },
    encryption: { columns: ['orders.price'] },
    audit: { enabled: true },
  },
  { masterKey },
);

try {
  const session = await scope.authenticate({ mockHumanDid: 'alice' });
  const agent = await scope.createAgentIdentity({ name: 'trading-agent', ownerDid: session.humanDid });

  const credential = await session.issueCredential({
    agent: agent.did,
    columns: ['orders.instrument', 'orders.quantity', 'orders.price'],
    actions: ['read'],
    expiresIn: '4h',
  });

  const presentation = await createPresentation(credential, agent.did, agent.signer, {
    audience: scope.verifierDid,
  });

  const result = await scope.query({
    agent: agent.did,
    credential: presentation,
    table: 'orders',
    sql: 'SELECT instrument, quantity, price FROM orders',
    requirePresentation: true,
  });
  console.log(result.rows);
} finally {
  await scope.close();
}
```

The SDK-direct flow signs a fresh, audience-bound VP in-process before querying. Remote MCP query paths require that VP and reject a raw credential, so users construct the presentation before calling MCP.

## Features

- **Cryptographic agent identity** -- freshly generated Ed25519 keypair + DID for every created agent. Stolen credentials fail owner-binding checks.
- **Column-level scope enforcement** -- SQL is parsed through PostgreSQL's native parser. Out-of-scope queries are rejected before execution, not filtered after.
- **Defense-in-depth encryption** -- AES-256-GCM per column, BYOK master key. Atomic key rotation and master-key rewrap without touching row data.
- **Agent-to-agent delegation** -- Supervisors delegate subsets of their scope to workers. Columns narrow, TTL shrinks, actions reduce. The narrowing is enforced at issuance; at query time the ScopeEngine verifies signatures, revocation, depth ceiling, and issuer-subject-owner bindings.
- **Tamper-evident audit** -- when audit is enabled, successful query records are Ed25519-signed and SHA-256 hash-chained. PostgreSQL triggers reject ordinary UPDATE/DELETE/TRUNCATE operations, but database owners and superusers can bypass or remove them.
- **Library + MCP surfaces** -- The same enforcement is available through the library and MCP server. Master key and DB credentials never cross the wire.
- **Delegation chain revocation** -- Revoke a parent credential and every downstream worker credential fails verification immediately.
- **OIDC authentication** -- Google, Microsoft, Keycloak, and AbaxxOne out of the box. Mock auth for development.

## Subpath exports

| Import | What you get |
|---|---|
| `@abaxxlabs/agents` | Agent identity, auth, credentials, crypto, storage interfaces |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management |
| `@abaxxlabs/agents/mcp` | MCP server factory and `agents mcp` CLI |
| `@abaxxlabs/agents/storage` | Storage backend composition |
| `@abaxxlabs/agents/sqlite` | SQLite backend (bun:sqlite / better-sqlite3) |
| `@abaxxlabs/agents/bootstrap` | `resolveMasterKeyFromEnv()` helper |

## MCP

AI agents connect via the [Model Context Protocol](https://modelcontextprotocol.io). The agent calls tools over stdio or HTTPS; the master key and database credentials stay in the MCP server process.

```bash
# stdio — Claude Desktop, Claude Code
agents mcp --db postgresql://localhost/mydb --mock "alice"

# HTTP — remote agents, TLS required
agents mcp --db postgresql://localhost/mydb --transport http --port 8443 \
  --tls-cert cert.pem --tls-key key.pem
```

**HTTP transport auth** every `GET /sse` and `POST /messages?sessionId=...` request must carry an `Authorization: Bearer <token>` header ([RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)). Requests without a valid token receive a `401` before the MCP SDK processes them. Tokens come from the embedder's `getValidTokens()` callback (`startMcpServer({ bearerAuth })`), which is re-read on every request so rotation is managed externally. The `agents mcp` CLI does not configure tokens itself, so running the HTTP transport from the CLI requires `--allow-no-auth` (development/test-only; any other `NODE_ENV` is a startup error). TLS is required for remote transport; `--insecure` (plaintext HTTP) is also development/test-only.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agents": {
      "command": "npx",
      "args": ["@abaxxlabs/agents", "mcp", "--db", "postgresql://localhost/mydb", "--mock", "alice"]
    }
  }
}
```

The `challenge` MCP tool is for Verifiable-Presentation freshness and replay protection, not transport authentication. It does not gate `/sse` or `/messages`; route access is controlled by the bearer guard described above.

Enforcement is identical across both MCP transports. The deployment shape determines where the trust boundary sits, not how enforcement works.

## Security model

- **Agents++ signatures use Ed25519** -- agent credentials and signed audit records use Ed25519/EdDSA; OIDC ID-token verification accepts an explicit asymmetric allowlist of RSA, RSA-PSS, ECDSA, and EdDSA algorithms
- **BYOK master key** -- a 64-character hexadecimal string (`[0-9a-fA-F]{64}`); Base64 and other encodings are rejected at bootstrap. You pass the key explicitly; `MasterKey` is a branded type that blocks leaks at compile time
- **Wrong-key boots fail loud** -- `AgentScope.create` throws immediately if existing column keys can't be decrypted
- **AES-256-GCM per column** -- each encryption uses a fresh random 96-bit IV; ciphertext length, type metadata, and database access patterns remain visible
- **Append-only audit for application roles** -- PostgreSQL triggers reject UPDATE/DELETE/TRUNCATE, but privileged database roles can bypass or remove them
- **VP audience binding** -- credentials can be bound to a specific server DID, preventing replay across instances
- **PKCE S256** on all OIDC flows; endpoint allowlists constrain authorization, token, and user-info destinations
- **Mock auth gated** -- `mockHumanDid` only works in `NODE_ENV=development` or `test`

## Free tier vs AbaxxOne

The open-source library is fully functional on its own -- identity, scoping, encryption, and audit within a single trust boundary. [AbaxxOne](https://abaxx.tech) unlocks cross-organizational trust.

| | Free (this library) | AbaxxOne |
|---|---|---|
| **Agent identity** | `did:key` (fresh per created agent, recoverable) | `did:key`, minted by this library |
| **Human (owner) identity** | `did:key` derived from the OIDC subject | whatever the tenant issued — `did:dht`, or `did:ion` for enterprise SSO users |
| **Credential issuer** | Human's self-issued DID | AbaxxOne, on behalf of your tenant |
| **Trust boundary** | Single server | Cross-org, federated |
| **Revocation** | Local (durable, cross-instance) | StatusList2021 (global, verifiable) |
| **Agent discovery** | Local registry | AbaxxOne directory |
| **Audit storage** | PostgreSQL | PostgreSQL + DWN (sovereign, portable) |

The transition is additive. Existing code, credentials, and query patterns stay the same -- you connect AbaxxOne services and unlock the network.

**On DID methods.** Agent DIDs are minted by this library as `did:key`. The *human owner* DID is
issued by the tenant -- `did:dht`, or `did:ion` for enterprise SSO users -- and only labels the
agent's owner: this library never resolves or verifies it. Credentials that AbaxxOne signs must
have a `did:key` or `did:dht` issuer, because that signature is verified against a resolved key.

## Development

Requires Node.js 20.3+ and PostgreSQL 16 for the full test suite (Postgres-gated tests skip gracefully without a live database).

```bash
bun install
npm test          # vitest
npm run build     # TypeScript → dist/
npm run typecheck
```

To run Postgres-gated tests locally:

```bash
docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine

DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres \
  node scripts/setup-test-db.mjs

DATABASE_URL=... npm test
```

## Documentation

The public documentation site is the canonical reference; the repository guides under `docs/` are the source it imports.

| Topic | Link |
|---|---|
| Documentation index | [abaxxtech.github.io/agents/documentation](https://abaxxtech.github.io/agents/documentation/) |
| Quick start | [guides/quick-start](https://abaxxtech.github.io/agents/documentation/guides/quick-start) |
| Installation | [guides/installation](https://abaxxtech.github.io/agents/documentation/guides/installation) |
| Playground (local) | [guides/playground](https://abaxxtech.github.io/agents/documentation/guides/playground) |
| Security and storage boundaries | [guides/security-and-storage-boundaries](https://abaxxtech.github.io/agents/documentation/guides/security-and-storage-boundaries) |
| Security | [security](https://abaxxtech.github.io/agents/documentation/security) |
| v0.11 migration | [migrations/v0.11](https://abaxxtech.github.io/agents/documentation/migrations/v0.11) |
| BYOK master key migration | [migrations/byok](https://abaxxtech.github.io/agents/documentation/migrations/byok) |
| Repository documentation index | [repository-documentation](https://abaxxtech.github.io/agents/documentation/repository-documentation) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

## License

[Apache-2.0](LICENSE)

---

<p align="center">
  Built by <a href="https://abaxx.tech">Abaxx Technologies</a>. Open-sourced through <a href="https://github.com/abaxxlabs">Abaxx Labs</a>.
</p>
