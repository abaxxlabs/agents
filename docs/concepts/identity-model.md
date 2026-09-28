---
id: identity-model
title: Identity model
description: How humans, agents, and servers relate in an Agents++ authorization flow.
slug: /concepts/identity-model
sidebar_position: 2
---

# Identity model

Agents++ separates the authority that authorizes an operation, the agent that presents the authorization, and the server that verifies and enforces it.

## Three roles

| Role | Responsibility |
|---|---|
| Human | Authenticates and authorizes an agent through the application. |
| Agent | Acts as the execution principal and presents a scoped credential or Verifiable Presentation. |
| Server | Verifies the proof, applies the query policy, and records the authorization result. |

The application remains responsible for deciding when an agent should run and which tools it may call. Agents++ supplies identity and authorization controls; it does not execute the agent or select a model.

## Human authentication

Production applications authenticate humans through the configured OpenID Connect provider. The authorization-code flow uses PKCE and a one-time state value before creating an `AuthenticatedSession`.

Development and tests may use the explicitly gated `mockHumanDid` path. Mock authentication is not available as a production authentication mechanism.

The session represents the human authority and carries the maximum scope that the application may issue for that session.

## Agent identity

When the application creates an agent, Agents++ assigns a DID and an Ed25519 keypair. The application associates that agent with the authenticated human owner when it creates the agent and issues credentials.

A DID is a cryptographic identifier. It is not, by itself, proof of a person's legal identity.

## Server identity and verifier binding

The server has a verifier DID, exposed by the SQL surface as `verifierDid`. A Verifiable Presentation can bind its audience to that DID. When the expected audience is checked, a presentation created for one verifier cannot be replayed against another verifier.

The verifier DID identifies the server context that accepts the proof. It does not replace credential signature verification, revocation checks, ownership checks, or the SQL scope policy.

## Identity boundary in one flow

```text
Human authenticates
  -> application creates an agent
  -> session issues a scoped credential
  -> agent presents the credential
  -> server verifies and enforces the scope
```
