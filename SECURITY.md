# Security Policy

## Supported Versions

Security updates are provided for the latest published release. Older releases are not supported. The current release is available on the [npm package page](https://www.npmjs.com/package/@abaxxlabs/agents).

## Reporting a Vulnerability

If you discover a security vulnerability in `@abaxxlabs/agents`, please report it responsibly.

**Email**: [security@abaxx.tech](mailto:security@abaxx.tech)

Include as much of the following as you can:

- Description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Affected version(s)
- Potential impact

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

- **Acknowledgement**: within 48 hours of receipt
- **Triage and severity assessment**: within 5 business days
- **Fix timeline**: depends on severity, but we aim to ship patches for critical issues within 14 days of confirmation

We will coordinate disclosure with the reporter. If you have a preferred disclosure timeline, include it in your report.

## Scope

The following are considered security issues for this library:

- **Key material handling** -- generation, storage, or exposure of Ed25519 private keys
- **Credential verification** -- bypasses in VC/VP signature verification, expiry checks, or scope enforcement
- **DID resolution** -- spoofing, substitution, or manipulation of DID documents
- **Authentication flows** -- OIDC integration vulnerabilities, PKCE bypasses, session handling flaws
- **Column encryption** -- weaknesses in AES-256-GCM encryption, key wrapping, or ciphertext handling
- **Audit trail integrity** -- tampering with signed audit records or hash chain
- **Scope enforcement** -- accessing columns or actions outside a credential's authorized scope
- **Delegation chain** -- privilege escalation through credential delegation

## Scope enforcement

The projection boundary rejects any SQL reference to columns outside the credential scope (CWE-285). `'projection'` is the only supported `scopeMode`.

## Trust controls

DID trust anchors and OIDC endpoint allowlists are separate controls. When consumers route credential verification through `AgentVerifier`, it checks issuer DIDs against the configured trust-anchor store; `VcVerifier` alone does not. OIDC endpoint allowlists constrain authorization, token, and user-info network destinations; they do not establish issuer trust.

## Verification timing

`credential.clockSkew` applies only to VP envelope timestamps (5 seconds by default, maximum 30 seconds). VC `nbf ?? iat` and `exp` checks are strict and receive no skew window, including for a VC inside a VP. OIDC ID-token verification is separate: `exp` is required and optional `nbf` is enforced strictly without leeway.

## JSON keystore file permissions

On Linux and macOS, the `JsonFileBackend` creates keystore files using `O_CREAT|O_EXCL|O_WRONLY` with mode `0600` (owner read/write only). The exclusive-create flag ensures the file never exists with wider permissions at any observable instant, and prevents symlink-based attacks in the temp-file path. A post-creation `stat` verifies the mode as defense in depth.

On Linux and CI, values in the JSON keystore are plaintext. Mode `0600` is access control, not encryption; the file owner, root, backups, and filesystem snapshots can read the contents. Production consumers can inject a secrets-manager-backed `KeystoreBackend`.

On Windows, Node.js POSIX file-mode arguments are not enforced by the OS. The keystore file inherits the parent directory's default ACL. **Deployment recommendation**: restrict the keystore directory (`%USERPROFILE%\.agents\`) ACL to the service principal running the agent process.

## Session envelope protection

Persisted session envelopes use HMAC-SHA256 over canonical JSON with an HKDF-derived key. This detects tampering but does not encrypt DIDs, email, or sanitized OIDC claims. Pending OAuth flows use a separate process-local `PendingFlowStore`: OAuth `state` is the key, `{ codeVerifier, expiresAt }` is the stored value, the default TTL is 10 minutes, and no OIDC nonce is generated or validated. Durable session storage does not make pending OAuth flows durable across instances.

## Column encryption limits

AES-256-GCM uses a fresh random 96-bit IV for each encryption. Uniqueness is probabilistic and depends on the operating system CSPRNG. Ciphertext length, database access patterns, wire-format fields, and logical type codes remain visible to database observers.

## Audit database privileges

The `agent_audit` triggers reject ordinary `UPDATE`, `DELETE`, and `TRUNCATE` operations by application roles. Database owners, superusers, and roles with sufficient DDL privileges can disable or remove these triggers. Production deployments should use a restricted runtime role separate from the owner or migration role.

## Out of Scope

- Vulnerabilities in upstream dependencies (pg, zod, libpg-query, etc.) -- please report those to the respective maintainers
- Issues requiring physical access to the host machine
- Denial-of-service attacks that require authenticated access
- Social engineering

## Bug Bounty

There is no bug bounty program at this time. We appreciate responsible disclosure and will credit reporters in release notes (unless you prefer to remain anonymous).
