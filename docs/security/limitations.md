---
id: security-limitations
title: Security limitations
description: Important limits and trust assumptions for Agents++ deployments.
slug: /security/limitations
sidebar_position: 2
---

# Security limitations

Agents++ provides independent identity, authorization, encryption, and audit controls. These controls work within explicit trust assumptions and do not replace database privileges, TLS, or secret-management practices.

## Authorization limits

The implemented business-data query policy is read-only PostgreSQL `SELECT` enforcement. It rejects unauthorized tables, columns, and mutations before execution.

A direct PostgreSQL connection bypasses this application-level policy. Production deployments must control database credentials and roles separately.

## Encryption limits

AES-256-GCM protects only columns explicitly configured for encryption. A database observer may still see schema metadata, ciphertext length, IV and tag metadata, and query or row access patterns.

The master key is supplied by the application. It must be stored in an appropriate secret-management system and never committed to source control.

## Audit limits

When enabled, successful scoped queries can produce signed, hash-chained records. This makes the application audit stream tamper-evident under the configured storage and key assumptions.

It is not an absolute immutability guarantee. Database owners, superusers, and roles able to remove or disable triggers remain outside the application-level audit boundary. Some rejection records may not have an agent signer available.

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
