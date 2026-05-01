# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.9.x   | Yes                |
| < 0.9   | No                 |

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

The projection boundary rejects any SQL reference to columns outside the credential scope (CWE-285). `'projection'` is the only supported `scopeMode`. The legacy `encryption-only` mode (which only guarded encrypted columns, leaving plaintext columns unprotected -- HIGH-5, Danny Chrastil, 2026-04-30) was removed along with the `AGENTS_ALLOW_LEGACY_SCOPE_MODE` env gate.

## JSON keystore file permissions

On Linux and macOS, the `JsonFileBackend` creates keystore files using `O_CREAT|O_EXCL|O_WRONLY` with mode `0600` (owner read/write only). The exclusive-create flag ensures the file never exists with wider permissions at any observable instant, and prevents symlink-based attacks in the temp-file path. A post-creation `stat` verifies the mode as defense in depth.

On Windows, Node.js POSIX file-mode arguments are not enforced by the OS. The keystore file inherits the parent directory's default ACL. **Deployment recommendation**: restrict the keystore directory (`%USERPROFILE%\.agents\`) ACL to the service principal running the agent process.

## Out of Scope

- Vulnerabilities in upstream dependencies (pg, zod, libpg-query, etc.) -- please report those to the respective maintainers
- Issues requiring physical access to the host machine
- Denial-of-service attacks that require authenticated access
- Social engineering

## Bug Bounty

There is no bug bounty program at this time. We appreciate responsible disclosure and will credit reporters in release notes (unless you prefer to remain anonymous).

## AbaxxOne OIDC — HIGH-1 closeout

The v0.5.0 white-box audit (Danny Chrastil, 2026-04-30) identified **HIGH-1**: the legacy module-level functions `authenticateWithOidc` and `completeOidcFlow` left CSRF state validation as an unenforced obligation on every consumer (CWE-352, CWE-639; OWASP API4:2023, ASVS V4.2.2 / V13.2.3). These entry points, the `VerifiedAuthState` brand machinery, and `src/auth/legacy-oidc.ts` / `src/auth/verified-auth-state.ts` were **removed in v1.0**. All AbaxxOne OIDC flows now go through `AbaxxOneOidcProvider`, which validates state end-to-end against its internal `PendingFlowStore` before any token exchange.
