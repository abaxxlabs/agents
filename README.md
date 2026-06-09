<p align="center">
  <h1 align="center">Agents++</h1>
  <p align="center"><strong>Agents are an attack surface. Hold yours accountable.</strong></p>
  <p align="center">Open trust infrastructure for autonomous AI agents.</p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@abaxxlabs/agents"><img src="https://img.shields.io/npm/v/@abaxxlabs/agents?style=flat-square" alt="npm version" /></a>
  <a href="https://github.com/abaxxlabs/agents/actions"><img src="https://img.shields.io/github/actions/workflow/status/abaxxlabs/agents/ci.yml?style=flat-square" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License" /></a>
</p>

---

Every AI agent is a potential threat actor. A stolen API key is indistinguishable from a legitimate one, a compromised agent can act with the full authority of whoever provisioned it, and there is no audit trail connecting actions to a responsible party.

**Three incidents in seven months tell the same story:**

| Incident | What happened |
|---|---|
| **Drift AI** (Aug 2025) | Stolen OAuth tokens impersonated a trusted agent across 700+ enterprise environments. Bearer tokens carry no delegation provenance. |
| **LiteLLM** (Mar 2026) | Backdoored packages harvested API keys across 95M monthly downloads. Stolen keys worked from attacker servers because they aren't bound to identity. |
| **Meta confused deputy** (Mar 2026) | An internal agent with valid perimeter credentials autonomously exposed proprietary code and user data. No delegation chain, no scoped authorization. |

The gap is structural: current infrastructure authenticates *applications* but cannot verify *which agent, authorized by whom, for what scope*. Agents++ closes it.

## How it works

```mermaid
flowchart LR
    H["Human\n(OIDC auth)"]
    H -->|"issues credential\ncolumns: price, qty"| A
    H -->|"issues credential\ncolumns: instrument"| B
    A["Agent A"] -->|query| SE
    B["Agent B"] -->|query| SE
    SE["ScopeEngine\n─────────────\n✓ verify credential\n✓ enforce projection\n✓ decrypt columns\n✓ sign audit record"]
    SE --> DB[("PostgreSQL\nAES-256-GCM\nper column")]
    SE --> AL["Audit trail\nEd25519-signed\nhash-chained"]
```

Same table. Same SQL. Agent A gets `price` and `quantity` in cleartext. Agent B gets `instrument` only. Querying an out-of-scope encrypted column throws `ScopeViolationError` -- it isn't filtered, it's rejected before execution.

## Before / after

**Before** -- trust your agent not to exceed its permissions:

```typescript
// Application checks before the query — a prompt-injected agent can route around these
if (!agent.hasPermission('price')) throw new Error('denied');
const result = await db.query('SELECT instrument, price FROM orders');
```

**After** -- the query layer makes it structurally impossible:

```typescript
const result = await scope.query({
  agent: agent.did,
  credential,           // VC: { columns: ['orders.instrument'], actions: ['read'] }
  table: 'orders',
  sql: 'SELECT instrument, price FROM orders',
  // 'price' is encrypted and out of scope → ScopeViolationError before execution
});
```

## Features

**Cryptographic agent identity.** Each agent owns an Ed25519 keypair and a DID. Every action is signed. Every credential chains back to the human who authorized it. Stolen credentials fail owner-binding checks -- possession alone is insufficient.

**Column-level scope enforcement.** The ScopeEngine parses SQL through PostgreSQL's native parser, extracts physical table references (CTE-aware), and rejects any query that touches columns outside the credential's scope -- before the query reaches the database.

**Defense-in-depth encryption.** Sensitive columns are AES-256-GCM encrypted at rest with per-column keys wrapped by a BYOK master key. Even with direct database access, encrypted data is unreadable without authorization. Key rotation and master-key rewrap are atomic, transactional operations.

**Agent-to-agent delegation.** Supervisors delegate subsets of their scope to workers. Columns must be a subset, actions must be a subset, TTL cannot exceed the source. Chains compose under the same rules -- every link narrows, never widens.

**Tamper-evident audit trail.** Every record is Ed25519-signed and SHA-256 hash-chained. PostgreSQL triggers block UPDATE and DELETE at the database level. Chain integrity is verifiable offline by anyone with the signing public keys.

**MCP and REST surfaces.** Ship as a library, an MCP server (stdio + HTTPS), or a REST API. Same enforcement everywhere. AI agents (Claude, GPT, etc.) connect through MCP; web apps and cross-language clients use REST. Master key and DB credentials never cross the wire.

## Install

```bash
npm install @abaxxlabs/agents
```

Peer dependencies for SQL enforcement:

```bash
npm install pg libpg-query
```

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

## How Agents++ compares

| Capability | Typical approach | Agents++ |
|---|---|---|
| Agent identity | API keys, no provenance | Verifiable credential chain (DID + VC) |
| Scope enforcement | Row-Level Security or app-level filtering | Column-level, credential-based, works with connection pools |
| Cross-org trust | Not addressed | Federated bilateral trust via AbaxxOne |
| Audit trail | Application logs | Cryptographically signed, hash-chained, externally verifiable |
| Delegation | Manual RBAC per agent | Credential delegation with automatic subset enforcement |
| Key management | Shared secrets, env vars | BYOK master key, per-column encryption, branded types prevent leaks |

## Subpath exports

| Import | What it provides |
|---|---|
| `@abaxxlabs/agents` | AgentIdentity, auth, credentials, crypto, storage interfaces |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management |
| `@abaxxlabs/agents/mcp` | MCP server factory and `agents mcp` CLI |
| `@abaxxlabs/agents/storage` | Storage backend composition |
| `@abaxxlabs/agents/sqlite` | SQLite backend (bun:sqlite / better-sqlite3) |
| `@abaxxlabs/agents/bootstrap` | `resolveMasterKeyFromEnv()` helper |
| `@abaxxlabs/agents/id-sdk-mcp` | Platform identity adapter (AbaxxOne) |

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

Use HTTP transport for production -- the agent calls over the network and never has direct access to the database or master key.

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

## Security model

- **Ed25519 only** -- no algorithm agility, no downgrade surface
- **BYOK master key** -- Agents++ never reads `process.env`; you pass the key explicitly. `MasterKey` is a branded type that blocks the buffer from leaking into untyped sinks at compile time
- **Wrong-key boots fail loud** -- `AgentScope.create` throws `MasterKeyMismatchError` immediately if existing column keys can't be decrypted
- **Column encryption** -- AES-256-GCM per column; `rotateColumnKey()` re-encrypts all rows atomically; `rewrapColumnKey()` migrates to a new master key without touching row data
- **Append-only audit trail** -- PostgreSQL triggers block UPDATE/DELETE; every record is Ed25519-signed and hash-chained
- **VP audience binding** -- credentials can be bound to a specific server DID, preventing replay across instances
- **PKCE S256** on all OIDC flows; SSRF guards on discovered endpoints
- **Mock auth gated** -- `mockHumanDid` only works in `NODE_ENV=development` or `test`

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for architecture decision records.

## Deployment modes

Agents++ ships as one npm package with multiple subpath exports. The deployment topology is your choice:

| Mode | Use when | Trust boundary |
|---|---|---|
| **Library** | Your backend wants scoped DB access for its own agents | Your application process |
| **MCP server** | AI agents (Claude Desktop, custom clients) need DB access across a process boundary | Standalone MCP process -- master key never crosses the wire |
| **REST server** | Web apps, cross-language clients, anything that can't speak MCP | Standalone REST process -- HTTPS + session auth |

Enforcement is identical across all three modes. The deployment shape determines *where* the trust boundary sits, not *how* enforcement works.

```bash
# MCP (Claude Desktop, Claude Code)
agents mcp --db postgresql://localhost/mydb --mock "Trader-1"

# REST
agents serve --db postgresql://localhost/mydb --port 3100
```

## Free tier vs AbaxxOne

The open-source library is genuinely useful on its own -- identity, scoping, encryption, and audit within a single trust boundary. AbaxxOne unlocks cross-organizational trust.

| | Free tier | AbaxxOne |
|---|---|---|
| **Agent identity** | `did:key` (deterministic, recoverable from OIDC) | `did:dht` (HSM-backed, institutional) |
| **Credential issuer** | Human's self-issued DID | Organization's DID |
| **Trust boundary** | Single server | Cross-org, federated |
| **Revocation** | Local (durable, cross-instance) | StatusList2021 (global, verifiable) |
| **Agent discovery** | Local registry | AbaxxOne directory |
| **Audit storage** | PostgreSQL | PostgreSQL + DWN (sovereign, portable) |

The transition is additive. Existing code, credentials, and query patterns don't change -- you connect AbaxxOne services and unlock the network.

## Documentation

| Topic | Link |
|---|---|
| Full technical specification | [Documentation v0.11.4](docs/) |
| v0.11 migration guide | [docs/migration-v0.11.md](docs/migration-v0.11.md) |
| BYOK master key migration | [docs/migration-byok.md](docs/migration-byok.md) |
| Architecture decisions | [docs/DECISIONS.md](docs/DECISIONS.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Development

Requires Node.js 20.3+ and PostgreSQL 16 for the full test suite (Postgres-gated tests skip gracefully without a live database).

```bash
npm install
npm test          # vitest, ~15s
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

## AI-Assisted Development

This repo uses [gstack](https://github.com/garrytan/gstack) for AI-assisted development workflows. gstack is **required** for all Claude Code and Codex sessions.

**One-time setup (each developer):**

```bash
git clone --depth 1 https://github.com/garrytan/gstack.git ~/.claude/skills/gstack
cd ~/.claude/skills/gstack && ./setup --team
```

After install, skills like `/qa`, `/ship`, `/review`, `/investigate`, and `/browse` are available in Claude Code sessions. A pre-tool hook in `.claude/settings.json` enforces the requirement -- sessions without gstack installed will be blocked from using skills.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
