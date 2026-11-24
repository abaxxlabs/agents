---
id: playground
title: Playground
description: Run the self-service Agents++ order-book demo locally with Docker.
sidebar_position: 3
---

# Playground

The Playground is an interactive demo that shows how Agents++ controls which order book data an agent can read. You can sign in as a demo user, create an agent with its own identity, and choose which columns its credential allows it to query.

Use the SQL console to test those permissions or delegate the same or a narrower set of permissions from a supervisor agent to a worker. The demo also shows how selected columns are encrypted at rest and lets you inspect a signed, hash-chained audit trail.

The Playground runs entirely on your machine in Docker. No provider API key is required.

## Prerequisites

- Docker Engine 28.3.3 or newer
- Docker Compose 2.20 or newer

The Playground relies on Docker Engine 28.3.3 or newer to keep its published port accessible only from your machine.

## Run the playground locally {#run-it-locally}

From `demo/playground` directory in a clean checkout of the agents++ repository, run:

```bash
docker compose up --build
```

Docker Compose builds the agents++ package from the repository and starts a dedicated PostgreSQL 16 database. Once the database is healthy, Compose runs the setup and starts the Playground. Setup can run more than once, and the Playground starts only after setup succeeds.

Open the Playground at [http://127.0.0.1:3100](http://127.0.0.1:3100). To check readiness from a second terminal, run:

```bash
curl -fsS http://127.0.0.1:3100/readyz
```

### Use a different port {#port-already-in-use}

The Playground publishes its application port only on the host’s loopback interface. PostgreSQL stays on the Docker network. If port 3100 is already in use, set `PLAYGROUND_PORT` to another available port:

```bash
PLAYGROUND_PORT=3110 docker compose up --build
```

With this setting, open the Playground at [http://127.0.0.1:3110](http://127.0.0.1:3110).

### Stop and reset the Playground {#stop-and-reset}

To stop the Playground and keep the database and generated master key in their named volumes, run:

```bash
docker compose down
```

To reset the Playground, delete the volumes containing the database and master key:

```bash
docker compose down --volumes
```

The next time you run `docker compose up --build`, the Playground creates a fresh database and master key.

## Test agent permissions {#what-to-try}

1. Sign in as a demo user. Choose `alice` for an unrestricted permission ceiling or `bob` for a ceiling limited to instrument, side, quantity, and status. The server assigns bob’s ceiling, as it would in production using identity provider groups.
2. Set up an agent with a `did:key` decentralized identifier (DID) and a private key encrypted using the master key.
3. Issue a credential and select the columns the agent can query. If you’re signed in as `bob`, selecting the `price` column returns a `ScopeExceedsCeilingError`.
4. Delegate permissions to a worker agent. Grant the worker some or all of the column permissions from the supervisor’s source credential. Delegation is limited to one hop: the worker cannot redelegate the credential.
5. Test the SQL policy in the SQL console by trying `SELECT *`, a `DELETE` statement, or a query that modifies data inside a common table expression (CTE). The policy rejects each query before execution.
6. Inspect the access comparison's Audit record metric to see whether the query or policy rejection has a saved record.

## Local boundaries

The Playground uses Alice and Bob as fixed, local mock identities for demonstration authentication. Signing in through the browser creates an opaque visitor session.

Scoped queries access a shared, read-only orders dataset through a single PostgreSQL connection pool used throughout the process. Each visitor’s agent identities, credentials, and audit chain are maintained in a private, in-memory SQLite store. The direct-SQL comparison routes execute against a disposable per-request copy of the plaintext fixture, so their mutations never persist.

The Playground manages the HTTP and network boundary and validates incoming requests. agents++ validates credentials and enforces agent ownership and query scope.

For instructions on manually setting up Node.js and PostgreSQL, using an external PostgreSQL database, or running verification commands, please refer to `demo/playground/README.md`.
