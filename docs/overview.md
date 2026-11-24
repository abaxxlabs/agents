---
id: overview
title: Overview
description: Start here to understand what Agents++ does and where to go next.
sidebar_position: 1
---

# Overview

Start here to understand what Agents++ does and where to go next.

AI agents are moving from tools to actors, initiating and coordinating actions across systems as delegated extensions of users and institutions, fundamentally changing how people and organizations interact with computers and the internet.

However, the systems these agents interact with were built for human-initiated activity, where identity, authorization, and accountability are applied at the user level. As agents become more autonomous, this creates a structural gap: the inability to reliably answer who an agent is, who authorized it, and what it is allowed to do.

Abaxx has spent seven years building globally resolvable identity infrastructure to answer these questions for humans. Agents++ extends that foundation to agents, applying the same cryptographic containers and logic to a new class of actors, enabling them to operate as trusted, verifiable extensions of the individuals and organizations they represent.

Agents++ provides the identity and authorization infrastructure to answer three questions at the application boundary: who is the agent, who authorized it, and with what scope. When auditing is enabled, successful scoped queries can produce signed, hash-chained audit evidence.

```text
Who is acting?
Who authorized it?
What data may it read?
```

## What can I do with agents++? {#what-agents-provides}

- Create a secure cryptographic identity for each agent you build.
- Grant agents permissions through verifiable credentials issued by a human.
- Enforce read-only PostgreSQL queries through `ScopeEngine`.
- Encrypt selected columns with AES-256-GCM.
- Enable auditing to generate signed, hash-chained audit evidence.
- Integrate Agents++ with applications and agent runtimes through MCP.

Agents++ is designed to work alongside your existing setup. It doesn’t execute AI agents, select models, orchestrate tools, authorize arbitrary external APIs, or replace PostgreSQL roles.

## How does agents++ work? {#how-the-pieces-fit}

1. A person signs in using the configured identity provider.
2. The application creates an agent and links it to its human owner.
3. The session issues a scoped, time-limited credential.
4. The agent provides the credential at the application boundary.
5. `ScopeEngine` verifies the proof and authorizes a PostgreSQL `SELECT`.
6. The application receives the authorized result and any accompanying audit evidence.

The authorization boundary is enforced before the query reaches PostgreSQL. Any query that references a table or column outside the credential scope is rejected, rather than being filtered after execution.

## Explore agents++ {#where-to-go-next}

- [Installation](guides/installation.md)
- [Quick start](guides/quick-start.md)
- [Authorization and Audit Model](concepts/overview.md)
- [Identity model](concepts/identity-model.md)
- [Authorization flow](concepts/authorization-flow.md)
- [Interfaces](interfaces)
- [Security limitations](security/limitations.md)
