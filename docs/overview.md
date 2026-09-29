---
id: overview
title: Overview
description: Start here to understand what Agents++ does and where to go next.
sidebar_position: 1
---

# Overview

Agents++ is an embeddable TypeScript library and middleware layer for agent identity, bounded authorization, and verifiable audit evidence.

It answers three questions at the application boundary:

```text
Who is acting?
Who authorized it?
What data may it read?
```

## What Agents++ provides

- Cryptographic identity for created agents.
- Human-to-agent authorization through verifiable credentials.
- Read-only PostgreSQL query enforcement through `ScopeEngine`.
- Optional AES-256-GCM encryption for selected columns.
- Signed and hash-chained audit evidence when auditing is enabled.
- MCP integration for applications and agent runtimes.

Agents++ does not execute AI agents, select models, orchestrate tools, authorize arbitrary external APIs, or replace PostgreSQL roles.

## How the pieces fit

1. A human authenticates through the configured identity provider.
2. The application creates an agent and associates it with the human owner.
3. The session issues a credential with a bounded scope and lifetime.
4. The agent presents the credential at the application boundary.
5. `ScopeEngine` verifies the proof and authorizes a PostgreSQL `SELECT`.
6. The application receives the permitted result and optional audit evidence.

The authorization boundary runs before the query reaches PostgreSQL. A query that references a table or column outside the credential scope is rejected rather than filtered after execution.

## Where to go next

- [Installation](guides/installation.md)
- [Quick start](guides/quick-start.md)
- [Core concepts](concepts/overview.md)
- [Identity model](concepts/identity-model.md)
- [Authorization flow](concepts/authorization-flow.md)
- [Interfaces](interfaces)
- [Security limitations](security/limitations.md)
