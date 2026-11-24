---
id: authorization-flow
title: Authorization flow
description: How Agents++ validates credentials and enforces a scoped PostgreSQL read.
slug: /concepts/authorization-flow
sidebar_position: 3
---

# Authorization flow

Agents++ enforces authorization before a business-data query reaches PostgreSQL. Its primary workflow is a read-only SQL process, rather than a general-purpose policy engine for arbitrary APIs.

## 1. Establish human authority

The application authenticates a human and receives an `AuthenticatedSession`, whose scope ceiling limits what it can authorize agents to do.

## 2. Create an agent

The application creates an agent identity and associates it with its human owner. The agent is assigned a DID and an Ed25519 key pair.

## 3. Issue a credential

The session issues a credential with a bounded scope, such as:

- Authorized columns.
- Authorized actions.
- Expiration time.
- Delegation depth policy where applicable.

Issuance validates the requested scope and lifetime against the session ceiling. The resulting credential cannot exceed the authority of the issuer.

## 4. Present the authorization

The agent presents its credential, or a Verifiable Presentation containing the credential, at the application boundary. Remote query paths may require a presentation bound to the server verifier DID.

## 5. Verify and enforce the query

`ScopeEngine` performs the runtime checks:

1. Verify the credential or presentation signatures and validity.
2. Check the subject, owner, issuer, revocation, and delegation bindings.
3. Parse the SQL statement using the PostgreSQL parser.
4. Reject mutations and references to anything beyond the declared table or columns.
5. Execute the original, authorized `SELECT` statement.
6. Decrypt only the selected encrypted columns permitted by the scope.
7. Record an audit event if auditing is enabled.

The SQL is validated but not rewritten or sanitized. Any out-of-scope query is rejected before execution.

## Delegation

A supervisor may issue a more narrowly scoped credential to a worker. The delegated credential may limit the permitted columns, actions, validity period, or delegation depth; however, it cannot exceed the scope of the source credential.

When the credential is used, the verifier checks the delegation chain and revocation status. Durable revocation across multiple instances requires an appropriate persistent store and deployment configuration.

## What the flow does not authorize

- Database writes, such as `INSERT`, `UPDATE`, or `DELETE`, through the business-data query path.
- Direct PostgreSQL connections outside `ScopeEngine`.
- The use of arbitrary external APIs or tools.
- Execution or orchestration of an AI model.
