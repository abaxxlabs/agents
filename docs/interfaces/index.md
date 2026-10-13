---
id: interfaces
title: Interfaces
description: The public package, SQL, MCP, storage, and bootstrap interfaces.
slug: /interfaces
sidebar_position: 1
---

# Interfaces

Agents++ exposes focused interfaces so consumers can select the boundary they need without importing every runtime dependency.

## TypeScript package surfaces

| Import | Surface |
|---|---|
| `@abaxxlabs/agents` | Agent identity, authentication, credentials, cryptographic helpers, storage contracts, and shared types. |
| `@abaxxlabs/agents/sql` | `AgentScope`, `ScopeEngine`, PostgreSQL query enforcement, and encrypted-column key management. |
| `@abaxxlabs/agents/mcp` | MCP server factory and MCP tool integration. |
| `@abaxxlabs/agents/id-sdk-mcp` | `connectIdSdkMcp` adapter to a vendored id-sdk-mcp server over local stdio. This is a separate client bridge, not the Agents++ MCP query server. |
| `@abaxxlabs/agents/storage` | Storage backend composition and shared storage contracts. |
| `@abaxxlabs/agents/sqlite` | SQLite persistence backend for supported internal storage use cases. |
| `@abaxxlabs/agents/bootstrap` | Master-key parsing and environment resolution helpers. |

`connectIdSdkMcp()` requires an id-sdk-mcp server with its runtime dependencies available. It starts the vendored server by default, or accepts `args` for a separately provisioned server.

## PostgreSQL interface

Use `AgentScope` when the application owns a PostgreSQL pool and needs query enforcement at the database boundary:

```typescript
import { AgentScope } from '@abaxxlabs/agents/sql';

const scope = await AgentScope.create(config, { masterKey });
const result = await scope.query({ agent, credential, table, sql });
```

The SQL interface is read-only for business-data queries. `ScopeEngine` rejects mutation statements and out-of-scope references before execution. It does not control direct PostgreSQL connections or unrelated external APIs.

## MCP interface

Agents can call the same enforcement layer through MCP. For local stdio development:

```bash
agents mcp --db postgresql://localhost/mydb --mock "alice"
```

For remote HTTP transport, configure TLS and transport authentication. The MCP server process keeps database credentials and the master key on the server side.

## MCP query limitation

Remote MCP queries require an agent-signed Verifiable Presentation. A raw Verifiable Credential is rejected as a bearer token.

MCP does not expose the agent's private signer or a presentation-creation tool. The client application must construct the VP before calling the MCP `query` tool.

Use the root package's public `createPresentation` helper with a signer held by the application and the target server's verifier DID (supplied by the server operator). Send the resulting VP as `credential`; create a fresh VP for each query:

```typescript
import { createPresentation } from '@abaxxlabs/agents';

const vp = await createPresentation(vcJwt, agentDid, agentSigner, {
  audience: verifierDid,
});
await mcpClient.callTool({
  name: 'query',
  arguments: {
    agent: agentDid,
    credential: vp,
    table: 'orders',
    sql: 'SELECT instrument FROM orders',
  },
});
```

`agentSigner` must already be available to the calling application (for example, from the [SDK-direct quick start](../guides/quick-start.md)); the MCP `create-agent` tool does not return a private signer. The `id-sdk-mcp` bridge is for identity SDK operations and does not create Agents++ query presentations.
