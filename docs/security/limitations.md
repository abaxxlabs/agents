---
id: security-limitations
title: Security limitations
description: Important limits and trust assumptions for Agents++ deployments.
slug: /security/limitations
sidebar_position: 2
---

# Security limitations

Read [Security boundaries](index.md) for the controls and their trust assumptions. This page covers additional deployment limits and operator responsibilities.

## Authorization limits

The [authorization boundary](index.md#authorization-boundary) applies only to queries routed through `ScopeEngine`; direct PostgreSQL connections bypass it. Production deployments must control database credentials and roles separately.

## Encryption limits

In addition to the metadata described in the [encryption boundary](index.md#encryption-boundary), a database observer can see IV and authentication-tag metadata. Store the application-supplied master key in an appropriate secret-management system.

## Audit limits

The [audit boundary](index.md#audit-boundary) explains tamper evidence, privileged-role exclusions, and why some rejection records may be unsigned.

## Revocation limits

Revocation checks depend on the selected store and its freshness:

- In-memory revocation state is process-local and does not survive a restart.
- Multi-instance deployments require durable storage and coherency configuration.
- A short propagation window may exist when revocation state is cached or polled between instances.

Revocation prevents acceptance only when the verifier actually performs the revocation check.

## Session and OIDC limits

Session envelopes protect integrity and authenticity, not confidentiality. Persisted identity claims can remain visible to the storage administrator.

The current OIDC provider flow uses issuer, audience, JWKS, PKCE, expiration, and state checks. It does not generate or validate an OIDC nonce, so deployments should preserve the provider and transport controls around the flow.

## Deployment responsibility

Agents++ does not make a privileged PostgreSQL role safe. Operators remain responsible for:

- Least-privilege database roles.
- TLS for remote transports.
- Secret and master-key management.
- Migration execution and rollback planning.
- Monitoring and retention of audit data.

See the [detailed security and storage boundaries guide](../guides/security-and-storage-boundaries.md) for the full implementation reference.
