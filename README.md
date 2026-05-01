# @abaxxlabs/agents

[![npm](https://img.shields.io/npm/v/@abaxxlabs/agents.svg)](https://www.npmjs.com/package/@abaxxlabs/agents)
[![CI](https://github.com/abaxxlabs/agents/actions/workflows/ci.yml/badge.svg)](https://github.com/abaxxlabs/agents/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Column-level access control for AI agents — enforced in the query layer, not the application.**

Two agents query the same table. They get completely different data — not because your code filters it, but because the query layer physically cannot return what the agent isn't credentialed for.

---

## The problem with application-level checks

AI agents get prompt-injected. Permission checks that happen before the query are bypassable — a compromised or manipulated agent can work around them entirely. Once data leaves the database unfiltered, you've already lost.

`@abaxxlabs/agents` moves enforcement into the query layer. Each agent carries a signed, scoped [Verifiable Credential](https://www.w3.org/TR/vc-data-model/). The ScopeEngine verifies it on every query, enforces the projection boundary, and decrypts only the authorized columns — before results leave the database.

---

## How it works

```mermaid
flowchart LR
    H["👤 Human\n(OIDC auth)"]
    H -->|"issues credential\ncolumns: price, qty"| A
    H -->|"issues credential\ncolumns: instrument"| B
    A["🤖 Agent A"] -->|query| SE
    B["🤖 Agent B"] -->|query| SE
    SE["ScopeEngine\n─────────────\n✓ verify credential\n✓ enforce projection\n✓ decrypt columns\n✓ sign audit record"]
    SE --> DB[("PostgreSQL\nAES-256-GCM\nper column")]
    SE --> AL["Audit trail\nEd25519-signed\nhash-chained"]
```

Same table. Same SQL. Agent A gets `price` and `quantity` in cleartext. Agent B gets `instrument` only. Querying an out-of-scope encrypted column throws `ScopeViolationError` — it isn't filtered, it's rejected before execution.

---

## What you get

- **Verifiable Credentials** — W3C-standard, signed, expiring, bound to the agent's DID
- **Column-level encryption** — AES-256-GCM per column, BYOK master key, atomic key rotation
- **Tamper-proof audit trail** — Ed25519-signed records, PostgreSQL-enforced append-only, hash-chained
- **Agent delegation** — supervisors can delegate a strict subset of their scope to workers, TTL-capped
- **MCP-native** — Claude, GPT, and any MCP-compatible agent works out of the box via `@abaxxlabs/agents/mcp`
- **Process isolation** — run as a separate process; the agent never touches DB credentials or the master key
- **Multiple backends** — PostgreSQL, SQLite, or in-memory storage; swap without changing application code

---

## Before / after

**Before** — trust your agent not to exceed its permissions:

```typescript
// Application checks before the query — a prompt-injected agent can route around these
if (!agent.hasPermission('price')) throw new Error('denied');
const result = await db.query('SELECT instrument, price FROM orders');
```

**After** — the query layer makes it structurally impossible:

```typescript
// Agent presents a signed credential — ScopeEngine verifies and enforces on every query
const result = await scope.query({
  agent: agent.did,
  credential,           // VC: { columns: ['orders.instrument'], actions: ['read'] }
  table: 'orders',
  sql: 'SELECT instrument, price FROM orders',
  // 'price' is encrypted and out of scope → ScopeViolationError before execution
});
```

---

## Install

```bash
npm install @abaxxlabs/agents
```

Peer dependencies for SQL enforcement:

```bash
npm install pg libpg-query
```

---

## Subpath exports

| Import | What it provides |
|--------|-----------------|
| `@abaxxlabs/agents` | AgentIdentity, auth, credentials, crypto, storage interfaces |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management |
| `@abaxxlabs/agents/mcp` | MCP server factory and `agents mcp` CLI |
| `@abaxxlabs/agents/storage` | Storage backend composition |
| `@abaxxlabs/agents/sqlite` | SQLite backend (bun:sqlite / better-sqlite3) |
| `@abaxxlabs/agents/bootstrap` | `resolveMasterKeyFromEnv()` helper |
| `@abaxxlabs/agents/id-sdk-mcp` | Platform identity adapter (AbaxxOne) |

---

## Quick start

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL },
    encryption: { columns: ['orders.quantity', 'orders.price', 'orders.counterparty'] },
    audit: { enabled: true },
  },
  { masterKey: resolveMasterKeyFromEnv() },
);

// Authenticate (mock in dev, OIDC in production)
const session = await scope.authenticate({ mockHumanDid: 'alice' });

// Create an agent with a DID
const agent = await scope.createAgent({ name: 'trading-agent', ownerDid: session.humanDid });

// Issue a scoped credential — alice decides what the agent can see
const credential = await session.issueCredential({
  agent: agent.did,
  columns: ['orders.instrument', 'orders.quantity'],
  actions: ['read'],
  expiresIn: '4h',
});

// Query — only authorized columns are decrypted
const result = await scope.query({
  agent: agent.did,
  credential,
  table: 'orders',
  sql: 'SELECT instrument, quantity FROM orders',
});
// Requesting 'price' or 'counterparty' → ScopeViolationError
```

---

## MCP server

AI agents connect directly via the [Model Context Protocol](https://modelcontextprotocol.io):

```bash
# stdio mode — Claude Desktop, Claude Code
agents mcp --db postgresql://localhost/mydb --mock "alice"

# HTTP mode — remote agents, master key stays in this process
agents mcp --db postgresql://localhost/mydb --transport http --port 8443 \
  --tls-cert cert.pem --tls-key key.pem
```

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

Use HTTP transport for production — the agent calls over the network and never has direct access to the database or master key.

---

## Delegation

Supervisors can delegate a strict subset of their scope to workers:

```typescript
const workerCred = scope.delegateCredential(supervisor.did, supervisorCred, {
  targetAgent: worker.did,
  columns: ['orders.instrument'],   // must be a subset of supervisor's scope
  actions: ['read'],
  expiresIn: '1h',                  // capped at supervisor's remaining TTL
});
```

---

## Security model

- **Ed25519 only** — no algorithm agility, no downgrade surface
- **BYOK master key** — the library never reads `process.env`; you pass the key explicitly. `MasterKey` is a branded type that blocks the buffer from leaking into untyped sinks at compile time
- **Wrong-key boots fail loud** — `AgentScope.create` throws `MasterKeyMismatchError` immediately if existing column keys can't be decrypted; no silent `[ENCRYPTED]` placeholders
- **Column encryption** — AES-256-GCM per column; `rotateColumnKey()` re-encrypts all rows atomically; `rewrapColumnKey()` migrates to a new master key without touching row data
- **Append-only audit trail** — PostgreSQL triggers block UPDATE/DELETE; every record is Ed25519-signed and hash-chained against the previous
- **VP audience binding** — credentials can be bound to a specific server DID, preventing replay across instances
- **PKCE S256** on all OIDC flows; SSRF guards on discovered endpoints
- **Mock auth gated** — `mockHumanDid` only works in `NODE_ENV=development` or `test`

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for architecture decision records.

---

## Development

Requires Node.js 20+ and PostgreSQL 16 for the full test suite (Postgres-gated tests skip gracefully without a live database).

```bash
npm install
npm test          # 1,287 tests, ~15s
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

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
