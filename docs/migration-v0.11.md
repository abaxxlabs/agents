# Migration Guide: v0.10 to v0.11

## What changed

v0.11 splits `@abaxxlabs/agents` into subpath exports. The main entry (`@abaxxlabs/agents`) is now SQL-free — it exports `AgentIdentity`, auth utilities, credential verification, audit logging, storage interfaces, and crypto primitives. SQL-specific code (`AgentScope`, `ScopeEngine`, column-key management) moved to `@abaxxlabs/agents/sql`.

**Why**: The identity layer, credential model, and storage interfaces have no inherent dependency on PostgreSQL. Splitting the entry points lets non-SQL consumers (MongoDB, GraphQL, MySQL, or identity-only use cases) depend on `@abaxxlabs/agents` without pulling in `pg`, `libpg-query`, or any SQL parsing logic. The credential model is query-engine agnostic — the same VC that authorizes a SQL column projection can authorize a MongoDB field filter or a GraphQL field resolver.

**New class: `AgentIdentity`** is the SQL-free identity layer extracted from `AgentScope`. It manages DIDs, OIDC authentication, agent registration, credential issuance, audit logging, and revocation. `AgentScope` now composes an `AgentIdentity` internally — its public API is unchanged.

When to use each:

- **`AgentIdentity`** — you need identity, credentials, and audit without SQL query enforcement. Non-SQL databases, identity-only services, credential issuance microservices.
- **`AgentScope`** — you need SQL column-level scoping, encrypted column management, and the ScopeEngine. PostgreSQL deployments with column-level access control.

---

## Subpath exports

| Import path | What it provides | Peer dependency timing |
|---|---|---|
| `@abaxxlabs/agents` | AgentIdentity, auth, credentials, storage interfaces, crypto, errors | No SQL peers |
| `@abaxxlabs/agents/sql` | AgentScope, ScopeEngine, column-key management | Requires `pg@8.20.0` + `libpg-query@17.7.3` |
| `@abaxxlabs/agents/mcp` | MCP server factory | Imports without SQL peers; SQL-backed startup/tools require them |
| `@abaxxlabs/agents/storage` | Storage backend composition utilities | No SQL peers |
| `@abaxxlabs/agents/sqlite` | SQLite storage backend (bun:sqlite / better-sqlite3) | Node requires `better-sqlite3@11.10.0`; Bun has built-in SQLite |
| `@abaxxlabs/agents/bootstrap` | `resolveMasterKeyFromEnv`, `parseMasterKeyHex` | No SQL peers |

---

## Import changes

### AgentScope

```typescript
// Before (v0.10):
import { AgentScope } from '@abaxxlabs/agents';

// After (v0.11):
import { AgentScope } from '@abaxxlabs/agents/sql';
```

### AgentIdentity (new)

```typescript
// v0.11 — SQL-free identity layer:
import { AgentIdentity } from '@abaxxlabs/agents';
```

### ScopeEngine

```typescript
// Before (v0.10):
import { ScopeEngine } from '@abaxxlabs/agents';

// After (v0.11):
import { ScopeEngine } from '@abaxxlabs/agents/sql';
```

### Column key functions

```typescript
// Before (v0.10):
import { loadColumnKeys, registerColumn, rotateColumnKey, rewrapColumnKey } from '@abaxxlabs/agents';

// After (v0.11):
import { loadColumnKeys, registerColumn, rotateColumnKey, rewrapColumnKey } from '@abaxxlabs/agents/sql';
```

### Storage, crypto, auth — unchanged

These were already on the main entry or their own subpaths and stay where they are:

```typescript
// These imports are unchanged in v0.11:
import { VcVerifier, AuditLogger, asMasterKey } from '@abaxxlabs/agents';
import { GenericOidcProvider, generateDidKey } from '@abaxxlabs/agents';
import { resolveMasterKeyFromEnv } from '@abaxxlabs/agents/bootstrap';
import { composeStorageBackend } from '@abaxxlabs/agents';
import { SqliteStorageBackend } from '@abaxxlabs/agents/sqlite';
```

---

## Type changes

Four types moved from `@abaxxlabs/agents` to `@abaxxlabs/agents/sql` because they reference `pg.Pool`:

```typescript
// Before (v0.10):
import type { AgentScopeInjections, AgentScopeInstance, QueryOptions, ScopedResult } from '@abaxxlabs/agents';

// After (v0.11):
import type { AgentScopeInjections, AgentScopeInstance, QueryOptions, ScopedResult } from '@abaxxlabs/agents/sql';
```

Types that stay on `@abaxxlabs/agents` (no pg dependency):

- `AgentScopeConfig` — describes what the scope is (OIDC, encryption columns, audit)
- `AuthOptions`, `AuthenticatedSession`, `CreateAgentOptions`, `RegisteredAgent`
- `AgentSigner`, `IdSdkInstance`, `IssueCredentialOptions`, `DelegateCredentialOptions`
- `AuditRecord`, `AuditEntry`, `VerificationResult`, `DecodedCredential`, `CredentialScope`
- All storage types: `StorageBackend`, `AgentStore`, `AuditStore`, `ContextStore`, `RevocationStore`, `SessionStore`

---

## Interface renames

v0.11 also removes the `I` prefix from storage interfaces. This landed alongside the split:

| v0.10 | v0.11 |
|---|---|
| `IAgentStore` | `AgentStore` |
| `IAuditStore` | `AuditStore` |
| `IContextStore` | `ContextStore` |
| `IRevocationStore` | `RevocationStore` |
| `ISessionStore` | `SessionStore` |

```typescript
// Before (v0.10):
import type { ISessionStore, IAuditStore } from '@abaxxlabs/agents';

// After (v0.11):
import type { SessionStore, AuditStore } from '@abaxxlabs/agents';
```

Find-and-replace: `IAgentStore` -> `AgentStore`, `IAuditStore` -> `AuditStore`, `IContextStore` -> `ContextStore`, `IRevocationStore` -> `RevocationStore`, `ISessionStore` -> `SessionStore`.

---

## Wrong-subpath guard

Importing `AgentScope` from the root entry (`@abaxxlabs/agents`) now fails at both layers:

- **TypeScript**: `AgentScope` is typed as `never` — any property access or call is a type error.
- **Runtime**: a `Proxy` throws `Error('AgentScope moved to @abaxxlabs/agents/sql in v0.11. Update your import.')` on any access.

If you see this error, change your import to `@abaxxlabs/agents/sql`.

---

## Peer dependency set

Consumers who only use the identity layer (`@abaxxlabs/agents`) no longer need `pg` installed. The SQL subpath requires the exact tested peer set `pg@8.20.0` and `libpg-query@17.7.3`.

- **Identity-only consumers**: remove `pg` from your dependencies if you don't use `AgentScope`, `ScopeEngine`, or the MCP server.
- **SQL consumers**: install `pg@8.20.0 libpg-query@17.7.3` when importing from `@abaxxlabs/agents/sql`.
- **MCP consumers**: `@abaxxlabs/agents/mcp` imports without manually installed peers so server factory types resolve in fresh consumers. Calling `startMcpServer()` or the SQL query tool still requires the same SQL peer set and throws a clear install message if it is missing.
- **SQLite consumers on Node.js**: install `better-sqlite3@11.10.0` when importing from `@abaxxlabs/agents/sqlite`; Bun consumers use built-in `bun:sqlite`.

---

## Migration checklist

1. **Update AgentScope imports**
   - [ ] `import { AgentScope } from '@abaxxlabs/agents'` -> `import { AgentScope } from '@abaxxlabs/agents/sql'`

2. **Update ScopeEngine imports**
   - [ ] `import { ScopeEngine } from '@abaxxlabs/agents'` -> `import { ScopeEngine } from '@abaxxlabs/agents/sql'`

3. **Update column-key function imports**
   - [ ] `loadColumnKeys`, `registerColumn`, `rotateColumnKey`, `rewrapColumnKey`, `encryptColumnInPlace`, `verifyAllColumnKeys` — from `@abaxxlabs/agents/sql`

4. **Update SQL-specific type imports**
   - [ ] `AgentScopeInjections`, `AgentScopeInstance`, `QueryOptions`, `ScopedResult` — from `@abaxxlabs/agents/sql`

5. **Rename I-prefixed interfaces**
   - [ ] `IAgentStore` -> `AgentStore`
   - [ ] `IAuditStore` -> `AuditStore`
   - [ ] `IContextStore` -> `ContextStore`
   - [ ] `IRevocationStore` -> `RevocationStore`
   - [ ] `ISessionStore` -> `SessionStore`

6. **Verify build**
   - [ ] `npx tsc --noEmit` passes
   - [ ] `npm test` passes

7. **Review peer dependencies**
   - [ ] If identity-only: confirm `pg` is not in your `dependencies`
   - [ ] If SQL or MCP runtime: install `pg@8.20.0 libpg-query@17.7.3`
   - [ ] If SQLite on Node.js: install `better-sqlite3@11.10.0`

---

## Errors are re-exported from both entries

All error classes (`ScopeViolationError`, `CredentialInvalidError`, `MasterKeyMismatchError`, etc.) are re-exported from `@abaxxlabs/agents/sql` to avoid `instanceof` breakage. You can import errors from either entry — they resolve to the same class.

```typescript
// Both work, same class identity:
import { ScopeViolationError } from '@abaxxlabs/agents';
import { ScopeViolationError } from '@abaxxlabs/agents/sql';
```
