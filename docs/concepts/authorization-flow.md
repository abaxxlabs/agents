---
id: authorization-flow
title: Authorization flow
description: How Agents++ validates credentials and enforces a scoped PostgreSQL read.
slug: /concepts/authorization-flow
sidebar_position: 3
---

# Authorization flow

Agents++ applies authorization before a business-data query reaches PostgreSQL. The central path is a read-only SQL flow, not a general-purpose policy engine for arbitrary APIs.

## 1. Establish human authority

The application authenticates a human and receives an `AuthenticatedSession`. The session has a scope ceiling that limits what it may authorize for agents.

## 2. Create an agent

The application creates an agent identity and associates it with the human owner. The agent receives a DID and an Ed25519 keypair.

## 3. Issue a credential

The session issues a credential containing a bounded scope, such as:

- Authorized columns.
- Authorized actions.
- Expiration time.
- Delegation depth policy where applicable.

Issuance validates the requested scope and lifetime against the session ceiling. The resulting credential cannot be wider than the authority that issued it.

## 4. Present the authorization

The agent presents its credential, or a Verifiable Presentation containing the credential, to the application boundary. Remote query paths can require a presentation bound to the server verifier DID.

## 5. Verify and enforce the query

`ScopeEngine` performs the runtime checks:

1. Verify credential or presentation signatures and validity.
2. Check subject, owner, issuer, revocation, and delegation bindings.
3. Parse the SQL statement with the PostgreSQL parser.
4. Reject mutations and references outside the declared table or columns.
5. Execute the original authorized `SELECT` statement.
6. Decrypt only selected encrypted columns that the scope permits.
7. Record an audit event when auditing is enabled.

The SQL is validated, not rewritten or sanitized. An out-of-scope query is rejected before execution.

## Delegation

A supervisor can issue a narrower credential to a worker. The delegated credential may reduce columns, actions, lifetime, or delegation depth, but it cannot expand the source credential.

The verifier checks the delegation chain and revocation state when the credential is used. Durable multi-instance revocation requires a suitable persistent store and deployment configuration.

## What the flow does not authorize

- Database writes such as `INSERT`, `UPDATE`, or `DELETE` through the business-data query path.
- Direct PostgreSQL connections outside `ScopeEngine`.
- Arbitrary external APIs or tools.
- Execution or orchestration of an AI model.
