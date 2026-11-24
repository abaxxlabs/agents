---
id: identity-model
title: Identity model
description: How humans, agents, and servers relate in an Agents++ authorization flow.
slug: /concepts/identity-model
sidebar_position: 2
---

# Identity model

agents++ distinguishes among the authority that approves an operation, the agent that presents the authorization, and the server that verifies and enforces it.

## Three roles

| Role | Responsibility |
|---|---|
| Human | Authenticates and authorizes an agent through the application. |
| Agent | Acts as the execution principal and presents a scoped credential or Verifiable Presentation. |
| Server | Verifies the proof, applies the query policy, and records the authorization result. |

The application remains responsible for deciding when an agent runs and which tools it can call. agents++ provides identity and authorization controls; it neither executes the agent nor selects a model.

## Human authentication

See [Human authentication](overview.md#human-authentication) for the production OIDC flow and the `AuthenticatedSession` scope ceiling.

Development and tests may use the explicitly gated `mockHumanDid` path. Mock authentication is not available as a production authentication mechanism.

## Agent identity

See [Identity](overview.md#identity) for the agent's DID, Ed25519 keypair, human-owner binding, and the distinction between a cryptographic identifier and legal identity.

## Server identity and verifier binding

The SQL surface exposes the server's verifier DID as `verifierDid`. See [Verifier binding](overview.md#verifier-binding) for presentation audience binding and cross-verifier replay protection.

The verifier DID identifies the server context that accepts the proof. It does not replace credential signature verification, revocation checks, ownership checks, or the SQL scope policy.

## Identity boundary in one flow

```text
Human authenticates
  -> application creates an agent
  -> session issues a scoped credential
  -> agent presents the credential
  -> server verifies and enforces the scope
```
