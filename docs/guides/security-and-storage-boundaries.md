# Security and Storage Boundaries

This guide describes the current cryptography, trust, storage, and audit behavior of Agents++. It is the canonical public reference for these boundaries.

## Cryptography Locations

Cryptographic implementation is split by responsibility. It is not centralized in `src/crypto/`, and there is no public `@abaxxlabs/agents/crypto` subpath.

| Responsibility | Internal location | Public import |
|---|---|---|
| JWT/JWS creation, decoding, and Ed25519 signature verification | `src/crypto/jwt.ts` | `@abaxxlabs/agents` |
| Master-key types and validation | `src/crypto/master-key.ts` | `@abaxxlabs/agents` |
| AES-256-GCM column encryption | `src/encryption/column.ts` | `@abaxxlabs/agents` |
| Session-envelope HKDF and HMAC | `src/storage/envelope-mac.ts` | `@abaxxlabs/agents` |
| OIDC ID-token and PKCE cryptography | `src/auth/` | `@abaxxlabs/agents` |
| Pool-dependent column-key operations | `src/sql/column-keys.ts` | `@abaxxlabs/agents/sql` |

Files named `src/crypto/aes.ts`, `src/crypto/hkdf.ts`, and `src/storage/session-envelope.ts` do not exist.

Created agents receive a fresh Ed25519 keypair from Node.js `generateKeyPairSync('ed25519')`. Deterministic identity derivation is a separate path used for specific identity flows. Agents++-issued JWS values use Ed25519/EdDSA, while OIDC ID-token verification permits a fixed asymmetric allowlist of RSA, RSA-PSS, ECDSA, and EdDSA algorithms.

The JWT helpers have deliberately narrow responsibilities:

- `createJwt()` signs the claims supplied by its caller.
- `decodeJwt()` decodes without verifying a signature.
- `verifyJwtSignature()` verifies an Ed25519 signature only. It does not validate `exp`, `nbf`, `iat`, issuer, audience, credential schema, or revocation.
- `VcVerifier` validates credential claims and policy.
- `src/auth/jwks-verify.ts` validates OIDC ID-token signatures and claims.
- Standalone MCP bearer tokens may be opaque values validated by the embedder and are not required to be JWTs.
- The REST `/auth/session` bearer token is an OIDC ID token verified against the configured JWKS, issuer, and audience. Development mode may use the explicit mock-auth path instead.
- After authentication, the server issues an opaque session token that clients send in the `x-session` header to authenticated REST and mounted MCP requests. All bearer-style tokens require TLS in transit.

`credential.clockSkew` applies only to the outer VP envelope's `nbf ?? iat` and `exp` checks. The default is 5 seconds and the maximum is 30 seconds. VC timestamps are authoritative and receive no skew window, including when the VC is wrapped in a VP. Temporal claims are currently optional on VC and VP inputs. OIDC ID tokens follow a separate strict path: `exp` is required and numeric, optional `nbf` is enforced without leeway, and no OIDC nonce is generated or validated by the current provider flow.

## Trust Controls

DID trust anchors and OIDC endpoint allowlists are independent controls.

- `LocalTrustAnchorStore` decides whether a credential issuer DID is trusted.
- `AgentVerifier` enforces the trust-anchor decision when consumers route verification through it. `VcVerifier` does not enforce the trust-anchor store by itself.
- OIDC endpoint validation constrains where authorization, token, and user-info requests may be sent. It does not make an issuer DID trusted.

Trust anchors have four sources:

| Source | Meaning | Persisted |
|---|---|---|
| `local` | The server's own DID; always trusted and not removable | No |
| `env` | Constructor-provided initial trusted servers | No |
| `api` | Programmatically added trust anchors | Yes, when a keystore is configured |
| `parent` | Issuer DID supplied by a caller after verifying an AbaxxOne parent credential | No; held in memory only |

Re-adding an existing DID through `addTrustedServer()` silently overwrites the entry, including its source and label, and does not emit a second discovery event.

`LocalTrustAnchorStore` does not bind a `parent` entry to a session or remove it automatically when a credential expires. Consumers that require session-scoped parent trust must rebuild or remove that in-memory entry themselves.

## Keystore and Audit Signing

The public `KeystoreBackend` contract contains exactly three methods:

- `read(key)` returns the stored value or `null`.
- `write(key, value)` uses upsert semantics.
- `delete(key)` is idempotent for missing keys.

On Linux and CI, the built-in `JsonFileBackend` stores plaintext JSON at `~/.agents/keystore.json` by default. Mode `0600` restricts filesystem access but does not encrypt values. Production consumers can inject a secrets-manager-backed `KeystoreBackend`.

Audit signatures do not all originate from the server-identity keystore. Successful scoped-query records are signed with the registered agent's `AgentSigner`; persisted agent private keys are wrapped in the `agents` table under the master key. Rejection records may be unsigned when no signer is available.

## Sessions and Pending OIDC Flows

Session envelopes are authenticated with HMAC-SHA256 over canonical JSON using a key derived from the master key with HKDF. This protects integrity and authenticity, not confidentiality: persisted DIDs, email, and sanitized OIDC claims remain readable to storage administrators.

`PendingFlowStore` and `SessionStore` serve different lifecycle stages:

| Store | Purpose | Lifetime and location |
|---|---|---|
| `PendingFlowStore` | Uses OAuth `state` as the key and stores `{ codeVerifier, expiresAt }`; no OIDC nonce; rejects CSRF, replay, and stale flows | In-process, single-use, 10-minute default TTL |
| `SessionStore` | Post-authentication session re-establishment envelopes | Memory, PostgreSQL, or SQLite with TTL and HMAC |

The public `AgentScope` identity and query flows do not call `storage.sessions`. The sessions member belongs to the composed `StorageBackend` so server or consumer orchestration can use it separately. The standalone REST server creates and wires its own session manager.

## Column Encryption Limits

Each AES-256-GCM encryption operation generates a fresh random 96-bit IV. IV uniqueness is probabilistic and depends on the operating system CSPRNG; Agents++ does not maintain a persistent counter or uniqueness registry.

Column encryption protects plaintext values but does not hide all metadata. A database observer can see ciphertext length, row and query access patterns, the wire-format version, IV, authentication tag, and logical type code. The visible type code also identifies encrypted SQL `NULL` values.

## Database Schema and Migrations

Migration `005_rename_tables.sql` renamed the original infrastructure tables to:

- `agents`
- `agent_keys`
- `agent_columns`
- `agent_audit`
- `agent_context`
- `agent_did_aliases`

Later migrations created:

- `revoked_credentials`
- `sessions`

The current audit table is `agent_audit`, not `agent_scope_audit`. Earlier migration files retain the legacy `agent_scope_*` names because migration 005 renames them.

Triggers on `agent_audit` reject ordinary `UPDATE`, `DELETE`, and `TRUNCATE` operations by application roles. They are not a security boundary against the database owner, a superuser, or another role able to disable or remove triggers. Production deployments should separate runtime and migration roles.

PostgreSQL migration execution is not tracked in a migration-history table. When a `migrations/` directory is available, `PostgresStorageBackend.initialize()` starts the ordered SQL migration sequence from its first file. If no directory is found, it skips SQL migrations and continues with storage startup. The published npm package does not include this directory, so consumers must apply PostgreSQL migrations through their deployment tooling. The sequence is not generally repeat-safe and must not be used as an apply-once boot migration runner.
