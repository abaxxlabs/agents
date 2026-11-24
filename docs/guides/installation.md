---
id: installation
title: Installation
description: Install Agents++ and prepare a PostgreSQL-backed scope.
sidebar_position: 1
---

# Installation

Install Agents++ and prepare a PostgreSQL-backed scope.

Agents++ is a TypeScript library and middleware layer for agent identity, authorization, encryption, and auditing. PostgreSQL query enforcement is available through the `sql` subpath.

## Requirements

- Node.js 20.3 or newer.
- PostgreSQL 16 for the SQL query path and the full integration test suite.
- A 32-byte master key encoded as exactly 64 hexadecimal characters if you use encrypted columns or durable storage.

## Install the SQL surface

```bash
npm install @abaxxlabs/agents pg@8.23.1 libpg-query@18.1.5
```

The `pg` package provides the PostgreSQL connection pool, while `libpg-query` parses PostgreSQL statements before the scope engine submits an authorized query to the database.

These versions correspond to the exact peer dependencies declared by the published agents++ package. Update them together when a newer compatible agents++ release becomes available.

The `latest` dist-tag identifies the currently recommended release. Releases merged to `main` are published directly under `latest`. To install a specific version, use a command such as `npm install @abaxxlabs/agents@0.60.1`.

For identity-only use cases, install the agents++ package without the PostgreSQL peer dependencies and import from `@abaxxlabs/agents`.

## Configure the master key

Generate the key and store it in your deployment’s secret manager. Never commit it to source control.

```bash
export AGENTS_MASTER_KEY="<64 hexadecimal characters>"
```

Read the key once at the application boundary:

```typescript
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';

const masterKey = resolveMasterKeyFromEnv();
```

`resolveMasterKeyFromEnv()` validates the exact length and hexadecimal format and returns the branded `MasterKey` value expected by `AgentScope.create()`.

## Apply PostgreSQL migrations

Apply the repository migrations using your deployment tooling before relying on durable PostgreSQL storage, revocation, sessions, encrypted columns, or audit tables. The published npm package does not include the repository’s migration directory.

## Verify the installation

After integrating agents++, run your application project’s typecheck and tests using its own scripts (the commands below are examples).

```bash
npm run typecheck
npm test
```

Tests requiring PostgreSQL are skipped when no database is available. They run when `DATABASE_URL` points to a configured PostgreSQL instance.
