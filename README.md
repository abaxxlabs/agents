<!-- TODO: hero banner — full-width visual, dark background, Agents++ wordmark + tagline -->

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
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#mcp--rest">MCP + REST</a> &bull;
  <a href="#security-model">Security</a> &bull;
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
npm install @abaxxlabs/agents@0.11.4 pg@8.20.0 libpg-query@17.7.3
```

## Quick start

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

// 1. Set up the scope engine
const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL },
    encryption: { columns: ['orders.quantity', 'orders.price'] },
    audit: { enabled: true },
  },
  { masterKey: resolveMasterKeyFromEnv() },
);

// 2. Authenticate and create an agent
const session = await scope.authenticate({ mockHumanDid: 'alice' });
const agent = await scope.createAgent({ name: 'trading-agent', ownerDid: session.humanDid });

// 3. Issue a scoped credential
const credential = await session.issueCredential({
  agent: agent.did,
  columns: ['orders.instrument', 'orders.quantity'],
  actions: ['read'],
  expiresIn: '4h',
});

// 4. Query — only authorized columns are decrypted
const result = await scope.query({
  agent: agent.did,
  credential,
  table: 'orders',
  sql: 'SELECT instrument, quantity FROM orders',
});
// Requesting 'price' → ScopeViolationError before the query reaches the database
```

## Features

- **Cryptographic agent identity** -- freshly generated Ed25519 keypair + DID for every created agent. Stolen credentials fail owner-binding checks.
- **Column-level scope enforcement** -- SQL is parsed through PostgreSQL's native parser. Out-of-scope queries are rejected before execution, not filtered after.
- **Defense-in-depth encryption** -- AES-256-GCM per column, BYOK master key. Atomic key rotation and master-key rewrap without touching row data.
- **Agent-to-agent delegation** -- Supervisors delegate subsets of their scope to workers. Columns narrow, TTL shrinks, actions reduce. The narrowing is enforced at issuance; at query time the ScopeEngine verifies signatures, revocation, depth ceiling, and issuer-subject-owner bindings.
- **Tamper-evident audit** -- when audit is enabled, successful query records are Ed25519-signed and SHA-256 hash-chained. PostgreSQL triggers reject ordinary UPDATE/DELETE/TRUNCATE operations, but database owners and superusers can bypass or remove them.
- **MCP + REST surfaces** -- Same enforcement as a library, an MCP server, or a REST API. Master key and DB credentials never cross the wire.
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

## MCP + REST

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

**REST** for web apps and cross-language clients:

```bash
agents serve --db postgresql://localhost/mydb --port 3100
```

The `challenge` MCP tool and `POST /challenge` endpoint are for Verifiable-Presentation freshness and replay protection, not transport authentication. They do not gate `/sse` or `/messages`; route access is controlled by the bearer guard described above.

Enforcement is identical across all three modes. The deployment shape determines where the trust boundary sits, not how enforcement works.

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
| **Agent identity** | `did:key` (fresh per created agent, recoverable) | `did:dht` (HSM-backed, institutional) |
| **Credential issuer** | Human's self-issued DID | Organization's DID |
| **Trust boundary** | Single server | Cross-org, federated |
| **Revocation** | Local (durable, cross-instance) | StatusList2021 (global, verifiable) |
| **Agent discovery** | Local registry | AbaxxOne directory |
| **Audit storage** | PostgreSQL | PostgreSQL + DWN (sovereign, portable) |

The transition is additive. Existing code, credentials, and query patterns stay the same -- you connect AbaxxOne services and unlock the network.

## Development

Requires Node.js 20.3+ and PostgreSQL 16 for the full test suite (Postgres-gated tests skip gracefully without a live database).

```bash
npm install
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

| Topic | Link |
|---|---|
| Documentation index | [docs/README.md](docs/README.md) |
| Security and storage boundaries | [docs/guides/security-and-storage-boundaries.md](docs/guides/security-and-storage-boundaries.md) |
| v0.11 migration guide | [docs/migrations/v0.11.md](docs/migrations/v0.11.md) |
| BYOK master key migration | [docs/migrations/byok.md](docs/migrations/byok.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

## License

[Apache-2.0](LICENSE)

---

<p align="center">
  Built by <a href="https://abaxx.tech">Abaxx Technologies</a>. Open-sourced through <a href="https://github.com/abaxxlabs">Abaxx Labs</a>.
</p>
