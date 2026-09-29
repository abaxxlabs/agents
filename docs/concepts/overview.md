---
id: concepts-overview
title: Core concepts
description: The identity, credential, scope, query, encryption, and audit model in Agents++.
slug: /concepts/overview
sidebar_position: 1
---

# Core concepts

Agents++ is an authorization and audit layer for AI-agent systems. It does not run the agent, choose a model, or orchestrate tools. It gives the application a way to identify an agent, bind it to human authority, enforce a read scope at the PostgreSQL boundary, and produce evidence of the decision.

## Identity

Each created agent receives a DID and an Ed25519 keypair. The agent identity is associated with the authenticated human owner. That owner binding is checked when credentials and delegation chains are used.

Agents++ keeps three roles separate:

- The **human** is the authority who authenticates and authorizes an agent.
- The **agent** is the execution principal that presents a scoped credential.
- The **server** is the verifier and policy enforcer for the request.

A DID is a cryptographic identifier. It is not, by itself, proof of a person's legal identity.

## Human authentication

Production human authentication uses the configured OpenID Connect provider. The authorization-code flow uses PKCE and a one-time state value before creating an `AuthenticatedSession`. Development and tests can use the explicitly gated mock identity path instead.

The session carries the human identity and the maximum scope that identity may issue. It can then create agents, issue credentials, and revoke credentials according to the configured policy.

## Verifier binding

The server's verifier DID identifies the server that is expected to validate a Verifiable Presentation. Remote query paths can bind the presentation audience to that DID, preventing a presentation created for one server from being replayed against another server.

## Credentials

A credential states what an agent may read, which actions are allowed, and how long the authorization remains valid. Credentials are signed and can be delegated to another agent only as a strict subset of the source scope.

## Scope enforcement

The `ScopeEngine` is the query boundary for PostgreSQL data:

1. Verify the credential, signatures, expiration, revocation, and delegation bindings.
2. Parse the requested SQL with the PostgreSQL parser.
3. Reject mutations and references outside the declared table or columns.
4. Execute only an authorized read.
5. Decrypt only columns that the scope permits, when column encryption is enabled.
6. Record an audit event, signed when the required signer is available, when audit logging is enabled.

The current implementation authorizes read-only `SELECT` queries. It does not filter unauthorized writes after execution and it does not authorize arbitrary external APIs.

## Encryption

Column encryption is an independent defense-in-depth layer. It protects selected plaintext values with AES-256-GCM and a caller-supplied master key. Encryption does not hide ciphertext length, access patterns, or every database metadata field.

## Audit

Successful scoped-query records can be signed with the agent signer and hash-chained into a tamper-evident audit trail. PostgreSQL triggers protect ordinary application-role updates, deletes, and truncates, but privileged database roles can bypass or remove those triggers.

## Delegation and revocation

A supervisor can issue a narrower credential to a worker. Revoking a parent credential invalidates downstream credentials when the verifier checks the delegation chain. The depth ceiling is part of the credential policy and prevents unbounded delegation.

Revocation visibility depends on the configured revocation store. In-memory state is process-local, and multi-instance deployments need a durable store and coherency configuration appropriate to their deployment.
