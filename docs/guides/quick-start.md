---
id: quick-start
title: Quick start
description: Create an agent, issue a scoped credential, sign a presentation, and execute a protected PostgreSQL read.
sidebar_position: 2
---

# Quick start

Create an agent, issue a scoped credential, sign a presentation, and execute a protected PostgreSQL read.

This quick start shows you how to use the agents++ SDK to run a protected, read-only PostgreSQL query in a single application process. You’ll create an agent, issue a narrowly scoped credential, use the agent signer to sign a Verifiable Presentation, and run the query through ScopeEngine.

## Prepare a disposable database

The `DATABASE_URL` below must point to an existing disposable PostgreSQL database. From a checkout of the Agents++ repository, run the repository migrations before starting the SDK. The npm package does not include the repository’s migration directory:

```bash
export DATABASE_URL='postgresql://localhost:5432/agents'
export AGENTS_MASTER_KEY="$(openssl rand -hex 32)"
export NODE_ENV=development
for migration in migrations/*.sql; do
  psql "$DATABASE_URL" -f "$migration"
done
```

Create the business table, seed a row, and encrypt `orders.price` in place:

```bash
psql "$DATABASE_URL" <<'SQL'
CREATE TABLE orders (
  id BIGSERIAL PRIMARY KEY,
  instrument TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  price NUMERIC NOT NULL
);

INSERT INTO orders (instrument, quantity, price)
VALUES ('BTC-USD', 2, 42000.00);
SQL

npx agents encrypt orders.price --db "$DATABASE_URL"
```

The encryption command records the column's original type so the SDK can decrypt it during an authorized query. The mock identity path is for development and testing only.

## Run the SDK-direct flow

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
  const agent = await scope.createAgentIdentity({
    name: 'trading-agent',
    ownerDid: session.humanDid,
  });

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

The database connection, master key, and agent signer stay in the application process. The query returns the authorized `orders.price` value, decrypted by the scope engine. The VP has a fresh nonce and is bound to this scope's verifier as its audience.

The value passed to `scope.query()` is the signed VP, not the raw credential. Setting `requirePresentation: true` ensures that the example exercises the same presentation requirement used by remote query paths.

## MCP limitation

The SDK-direct flow described above provides a self-contained, end-to-end path. The MCP `query` tool also requires an agent-signed Verifiable Presentation; requests containing the raw credential are rejected because it functions as a bearer token.

MCP does not provide a presentation-creation tool, so the client application must supply the VP. The transport does not expose the agent's private signer.

If the application has access to the agent signer and the server’s verifier DID, it can use the public `createPresentation(vcJwt, agentDid, agentSigner, { audience: verifierDid })` helper shown above. An MCP-only client without the agent signer cannot construct a VP from a raw VC using MCP tools alone.

## Example Limitations {#what-this-example-does-not-do}

- It does not execute an AI model or coordinate the use of tools.
- It does not authorize write operations; the implemented query policy is read-only.
- It does not replace PostgreSQL roles, deployment controls, or secret management.
