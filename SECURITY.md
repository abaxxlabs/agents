# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.11.x  | Yes                |
| 0.10.x  | Yes                |
| < 0.10  | No                 |

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

## Out of Scope

- Vulnerabilities in upstream dependencies (pg, zod, libpg-query, etc.) -- please report those to the respective maintainers
- Issues requiring physical access to the host machine
- Denial-of-service attacks that require authenticated access
- Social engineering

## Bug Bounty

There is no bug bounty program at this time. We appreciate responsible disclosure and will credit reporters in release notes (unless you prefer to remain anonymous).
