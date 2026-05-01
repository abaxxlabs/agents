# @abaxxlabs/agents

Identity and access control for AI agents on PostgreSQL.

Every agent gets a verifiable identity (DID), scoped credentials (Verifiable Credentials), and column-level encryption. Two agents querying the same table get different cleartext based on their credentials — enforced by the library, not by application logic.

```bash
npm install @abaxxlabs/agents
```

## Subpath exports

| Import | What it provides | SQL peers required |
|--------|-----------------|-------------------|
| `@abaxxlabs/agents` | AgentIdentity, auth, credentials, crypto, storage interfaces | No |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management | `pg` + `libpg-query` |
| `@abaxxlabs/agents/mcp` | MCP server factory and `agents mcp` CLI | No (SQL peers needed at runtime for query tool) |
| `@abaxxlabs/agents/storage` | Storage backend composition | No |
| `@abaxxlabs/agents/sqlite` | SQLite storage backend (bun:sqlite / better-sqlite3) | No |
| `@abaxxlabs/agents/bootstrap` | `resolveMasterKeyFromEnv()` bootstrap helper | No |
| `@abaxxlabs/agents/id-sdk-mcp` | Platform identity adapter (AbaxxOne MCP) | No |

## Quick start

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv(); // reads AGENTS_MASTER_KEY from env

const scope = await AgentScope.create(
  {
    database: { connectionString: process.env.DATABASE_URL },
    encryption: { columns: ['orders.quantity', 'orders.price'] },
    audit: { enabled: true },
  },
  { masterKey },
);

// Authenticate (mock in dev, OIDC in production)
const session = await scope.authenticate({ mockHumanDid: 'alice' });

// Create an agent
const agent = await scope.createAgent({ name: 'trading-agent', ownerDid: session.humanDid });

// Issue a scoped credential
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
```

## How it works

1. **Human authenticates** via Google, Microsoft, AbaxxOne, or any OIDC provider
2. **Human creates an agent** with a DID (did:key, Ed25519)
3. **Human issues a credential** specifying which columns the agent can access
4. **Agent queries** through the ScopeEngine
5. **ScopeEngine verifies** the credential (signature, expiry, scope, owner binding)
6. **ScopeEngine enforces** the projection boundary — rejects queries referencing out-of-scope encrypted columns, then decrypts authorized columns (AES-256-GCM)
7. **Audit record** is cryptographically signed and appended to a tamper-proof hash chain

## MCP server

AI agents can use this library through the [Model Context Protocol](https://modelcontextprotocol.io):

```bash
# stdio mode (Claude Desktop, Claude Code)
agents mcp --db postgresql://localhost/mydb --mock "alice"

# HTTP mode (remote clients — master key stays in this process)
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

For production, use HTTP transport. The master key and database credentials stay inside the MCP server process; the agent communicates over the network and never has access to either.

## Delegation

Supervisor agents can delegate a subset of their scope to worker agents:

```typescript
const workerCred = scope.delegateCredential(supervisor.did, supervisorCred, {
  targetAgent: worker.did,
  columns: ['orders.instrument', 'orders.quantity'], // must be a subset
  actions: ['read'],
  expiresIn: '1h',                                   // capped at supervisor TTL
});
```

## Security

- **Ed25519 only** — no algorithm agility
- **BYOK master key** — the library never reads `process.env.AGENTS_MASTER_KEY`; you pass the key explicitly at `AgentScope.create`. The `MasterKey` branded type blocks the buffer from leaking into untyped sinks at compile time. `AgentScope.close()` zeroes the primary copy on teardown.
- **Wrong-key boots fail loud** — if column keys exist in the database but cannot be decrypted with the supplied master key, `AgentScope.create` throws `MasterKeyMismatchError` immediately
- **Column encryption** — AES-256-GCM per column; keys wrapped with the master key. Key rotation re-encrypts all rows atomically
- **VP audience binding** — credentials can be bound to a specific server's `verifierDid`, preventing replay across servers
- **Append-only audit trail** — PostgreSQL triggers block UPDATE/DELETE; each record is Ed25519-signed and hash-chained
- **Mock auth gated** — `mockHumanDid` only works when `NODE_ENV=development` or `NODE_ENV=test`
- **PKCE S256** on all OIDC flows; SSRF guards on discovered endpoints

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for architecture decision records.

## Development

Requires Node.js 20+ and PostgreSQL 16 for the full test suite (Postgres-gated tests skip gracefully without a live database).

```bash
npm install
npm test          # unit + integration suite
npm run build     # TypeScript → dist/
npm run typecheck # type check only
```

To run Postgres-gated tests locally:

```bash
# Start a Postgres instance (any method)
docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine

DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres \
  node scripts/setup-test-db.mjs  # runs migrations

DATABASE_URL=... npm test
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
