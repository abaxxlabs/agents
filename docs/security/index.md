---
id: security
title: Security boundaries
description: The implemented authorization, encryption, authentication, and audit limits of Agents++.
slug: /security
sidebar_position: 1
---

# Security boundaries

Agents++ provides several independent controls. None of them should be treated as a replacement for least-privilege database roles, TLS, secret management, or operational separation.

## Authorization boundary

The credential and delegation chain are verified at the PostgreSQL query boundary. The current query policy is read-only: `SELECT` statements can be authorized by table and column scope, while mutations and out-of-scope references are rejected before execution.

## Identity and authentication

Agents receive cryptographic identity material and are bound to the human owner represented by the credential chain. Production human authentication uses the configured OIDC provider. Mock human identity is limited to development and test environments.

OIDC authentication uses an authorization-code flow with PKCE and a one-time state value. The current provider flow does not use an OIDC nonce, so deployments should rely on the configured issuer, audience, JWKS, PKCE, state, and transport controls as separate checks.

## Encryption boundary

AES-256-GCM column encryption protects selected values at rest. It does not hide ciphertext length, query and row access patterns, or all database metadata. The master key must be supplied by the application and must not be committed to source control.

## Audit boundary

When enabled, successful scoped queries can produce signed, hash-chained audit records. Application-role triggers reject ordinary changes to the audit table. Database owners, superusers, and roles able to remove or disable triggers remain outside that application-level boundary.

Audit evidence is tamper-evident under those trust assumptions. It is not a guarantee that a privileged database operator cannot remove, replace, or roll back stored records. Rejection records may not have an agent signer available.

## Operational limits

- Session envelopes protect integrity and authenticity, not confidentiality. Persisted identity claims remain visible to the storage administrator.
- Only configured columns are encrypted. Schema metadata, ciphertext length, and query and row access patterns can remain visible.
- A direct PostgreSQL connection bypasses the `ScopeEngine` projection boundary. Database roles and connection management remain part of the deployment security model.
- Revocation checks depend on the selected store and its freshness across instances. Durable multi-instance deployments must not rely on an in-memory store.
- A read-only application policy does not make privileged PostgreSQL roles harmless. PostgreSQL owners and superusers remain outside the application authorization boundary.

## Transport boundary

Remote MCP HTTP transport requires TLS and bearer authentication. The challenge endpoint is for Verifiable Presentation freshness and replay protection; it is not a replacement for transport authentication.

## Detailed reference

Read the [full security and storage boundaries guide](../guides/security-and-storage-boundaries.md) for cryptography locations, trust anchors, sessions, migrations, and storage-specific limits.
