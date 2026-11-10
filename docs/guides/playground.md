---
id: playground
title: Playground
description: Run the self-service Agents++ order-book demo locally with Docker.
sidebar_position: 3
---

# Playground

The Playground is a self-service demo of Agents++ on an order book: agent identity, column-scoped SQL, supervisor-to-worker delegation, columns encrypted at rest, and a signed, hash-chained audit trail. It runs entirely on your machine in Docker and needs no provider API key.

## Prerequisites

- Docker Engine 28.3.3 or newer
- Docker Compose 2.20 or newer

Older Docker Engine releases do not provide the same loopback-publishing guarantees.

## Run it locally

From `demo/playground` in a clean checkout:

```bash
docker compose up --build
```

Open [http://127.0.0.1:3100](http://127.0.0.1:3100). Compose builds the repository package, starts a dedicated PostgreSQL 16 database, runs the idempotent setup after PostgreSQL is healthy, and starts the Playground only after setup succeeds. From a second terminal, confirm readiness:

```bash
curl -fsS http://127.0.0.1:3100/readyz
```

### Port already in use

The application port is published on host loopback only; PostgreSQL is not published to the host. Select another loopback port without changing the container:

```bash
PLAYGROUND_PORT=3110 docker compose up --build
```

### Stop and reset

`docker compose down` stops the stack and keeps the database and generated master key in named volumes. `docker compose down --volumes` removes them; the next `docker compose up --build` creates a fresh database and key.

## What to try

1. Authenticate as `alice` (unrestricted ceiling) or `bob` (ceiling `[instrument, side, quantity, status]` assigned server-side, as it would come from IdP groups in production).
2. Create an agent; it receives a `did:key` DID and a private key encrypted with the master key.
3. Issue a credential by checking columns. As `bob`, checking `price` returns `ScopeExceedsCeilingError`.
4. Delegate from a supervisor to a worker a subset no wider than the source credential; the chain cannot widen the scope.
5. In the SQL console, `SELECT *`, `DELETE`, and hidden mutations in CTEs are rejected before execution.
6. Inspect the audit trail: records are signed and chained to the previous record.

## Local boundaries

`alice` and `bob` are fixed local mock identities, not production authentication. Each browser login creates an isolated visitor session backed by its own database. The Playground owns the HTTP and network boundary and validates request input; Agents++ validates credentials and enforces agent ownership and query scope.

For manual Node.js/PostgreSQL setup, external PostgreSQL, and verification commands, see the Playground reference at `demo/playground/README.md`.
