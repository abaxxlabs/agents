---
id: quick-start
title: Quick start
description: Create an agent, issue a scoped credential, sign a presentation, and execute a protected PostgreSQL read.
sidebar_position: 2
---

# Quick start

This example uses the SDK directly in one application process. It creates an agent, issues a narrow credential, signs a Verifiable Presentation with the agent signer, and executes a read-only PostgreSQL query through the scope engine.

## Prepare a disposable database

The `DATABASE_URL` below must point to an existing disposable PostgreSQL database. From a checkout of the Agents++ repository, apply the repository migrations before starting the SDK. The npm package does not include the repository migration directory:

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

The encryption command records the original type of the column so the SDK can decrypt it during an authorized query. The mock identity path is only for development and tests.

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
  const agent = await scope.createAgent({
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

The database connection, master key, and agent signer remain in the application process. The query returns the authorized `orders.price` value decrypted by the scope engine. The VP has a fresh nonce and is audience-bound to this scope's verifier.

The value passed to `scope.query()` is the signed VP, not the raw credential. Setting `requirePresentation: true` makes the example exercise the same presentation requirement used by remote query paths.

## MCP limitation

The SDK-direct flow above is the self-contained end-to-end path. The MCP `query` tool also requires an agent-signed Verifiable Presentation; sending the raw credential is rejected because it would be a bearer token.

MCP has no presentation-creation tool, so the client application must supply the VP. The transport never exposes the agent's private signer.

## What this example does not do

- It does not execute an AI model or orchestrate tools.
- It does not authorize writes; the implemented query policy is read-only.
- It does not replace PostgreSQL roles, deployment controls, or secret management.
