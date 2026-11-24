---
id: concepts-overview
title: Authorization and Audit Model
description: The identity, credential, scope, query, encryption, and audit model in Agents++.
slug: /concepts/overview
sidebar_position: 1
---

# Authorization and Audit Model

The identity, credential, scope, query, encryption, and audit model in Agents++.

Agents++ is an authorization and audit layer for AI agent systems. It does not execute agents, select models, or orchestrate tools. Instead, it enables applications to identify agents, bind them to human authority, enforce read scopes at the PostgreSQL boundary, and generate audit evidence for successful scoped queries when auditing is enabled.

## Identity

Each agent receives a DID and an Ed25519 keypair when created. Its identity is linked to the authenticated human owner, and that binding is checked when credentials and delegation chains are used.

Agents++ keeps three roles separate:

- The **human** authenticates and authorizes the agent.
- The **agent** submits the request using a scoped credential.
- The **server** verifies the request and enforces policy.

A DID is a cryptographic identifier; it does not, in and of itself, establish a person's legal identity.

## Human authentication

In production, human authentication uses the configured OpenID Connect provider. The authorization code flow employs PKCE and a one-time state value before creating an `AuthenticatedSession`. Development and testing may instead use the explicitly gated mock identity path.

The session carries the human identity and defines the maximum scope that identity may issue. It can then create agents, issue credentials, and revoke them according to the configured policy.

## Verifier binding

The server's verifier DID identifies the server expected to validate a Verifiable Presentation. Remote query paths can bind the presentation’s audience to that DID, preventing a presentation created for one server from being replayed against another.

## Credentials

A credential specifies what an agent may read, which actions it may perform, and how long the authorization remains valid. Credentials are signed and can be delegated to another agent only with a scope no wider than the source's scope.

## Scope enforcement

The `ScopeEngine` is the query boundary for PostgreSQL data:

1. Verify credentials, signatures, expiration, revocation, and delegation bindings.
2. Parse the requested SQL using the PostgreSQL parser.
3. Reject mutations and references outside the single declared table or its permitted columns.
4. Execute only authorized reads.
5. When column encryption is enabled, decrypt only columns that the scope permits.
6. When audit logging is enabled, record an audit event, signed when the required signer is available.

The current implementation authorizes read-only `SELECT` queries. It does not filter unauthorized writes after execution, nor does it authorize arbitrary external APIs.

## Encryption

Column encryption is an independent defense-in-depth layer. It protects selected plaintext values with AES-256-GCM and a caller-supplied master key. Encryption does not hide ciphertext length, access patterns, or every database metadata field.

## Audit

Successful scoped-query records can be signed with the agent signer and hash-chained into a tamper-evident audit trail. PostgreSQL triggers protect ordinary application-role updates, deletes, and truncates, but privileged database roles can bypass or remove those triggers.

## Delegation and revocation

A supervisor can issue a narrower credential to a worker. Revoking a parent credential invalidates downstream credentials when the verifier checks the delegation chain. The depth ceiling is part of the credential policy and prevents unbounded delegation.

Revocation visibility depends on the configured revocation store. In-memory state is process-local, and multi-instance deployments need a durable store and coherency configuration appropriate to their deployment.
