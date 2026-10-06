---
id: installation
title: Installation
description: Install Agents++ and prepare a PostgreSQL-backed scope.
sidebar_position: 1
---

# Installation

Agents++ is a TypeScript library and middleware layer for agent identity, authorization, encryption, and audit. The PostgreSQL query-enforcement surface is available through the `sql` subpath.

## Requirements

- Node.js 20.3 or newer.
- PostgreSQL 16 for the SQL query path and the full integration test suite.
- A 32-byte master key represented as exactly 64 hexadecimal characters when using encrypted columns or durable storage.

## Install the SQL surface

```bash
npm install @abaxxlabs/agents@0.11.4 pg@8.20.0 libpg-query@17.7.3
```

The `pg` package provides the PostgreSQL pool. `libpg-query` parses PostgreSQL statements before the scope engine sends an authorized query to the database.

These versions match the exact peer dependencies declared by the published Agents++ package. Update them together when a newer compatible Agents++ release is published.

For identity-only use cases, install the Agents++ package without the PostgreSQL peers and import from `@abaxxlabs/agents`.

## Configure the master key

Generate and store the key through your deployment secret manager. Do not commit it to source control.

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

Apply the repository migrations through your deployment tooling before relying on durable PostgreSQL storage, revocation, sessions, encrypted columns, or the audit tables. The published npm package does not include the repository migration directory.

## Verify the installation

```bash
npm run typecheck
npm test
```

The PostgreSQL-gated tests skip when no database is available. They run when `DATABASE_URL` points to a configured PostgreSQL instance.
