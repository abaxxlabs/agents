# ADR: REST/MCP shared API boundary

**Status:** Accepted for implementation planning
**Date:** 2026-04-29
**Jira:** ABXAGNTS-310
**Epic context:** ABXAGNTS-296 release readiness; downstream implementation under ABXAGNTS-297 server readiness
**Related tickets:** ABXAGNTS-311, ABXAGNTS-312, ABXAGNTS-313, ABXAGNTS-314, ABXAGNTS-315, ABXAGNTS-316, ABXAGNTS-252, ABXAGNTS-295

## Context

MCP ships with the library, while the REST server lives in `packages/server`. Today the active MCP tools in `src/mcp/tools.ts` call `AgentScope`, `AuthenticatedSession`, and `AuditLogger` directly. The REST routes in `packages/server/src/index.ts` call the same lower-level objects directly, but with separate validation, error rendering, rate limiting, session handling, and route-specific authorization checks.

`src/mcp/rest-bridge.ts` already exists as a design stub for making MCP tools call REST endpoints. That bridge is not wired into the active server. It demonstrates endpoint parity, but it would make REST the canonical implementation surface and would require MCP to know a REST base URL.

The release risk is drift: public MCP tool behavior could lock before REST hardening finishes, and duplicated query, audit, identity, validation, rate-limit, and error behavior could then diverge across transports.

## Decision

Use transport-neutral application services as the shared boundary. REST routes and MCP tools should validate transport shape, resolve transport authentication/session context, call shared services, and render transport-specific responses. The shared services, not REST endpoints, are the canonical implementation surface.

The selected direction is to replace the REST bridge with shared services. Do not wire `src/mcp/rest-bridge.ts` as the default MCP implementation before publish. Under ABXAGNTS-311, either delete the bridge stub and its tests or keep a clearly marked REST-backed adapter only for future gateway deployments. It must not be the canonical path for in-process MCP.

## Target Shape

Shared services should be grouped by domain operation:

- `QueryService`: executes scoped SQL queries, owns query acceptance checks, passes org/session context, enforces row limits, and emits/audits rejections consistently.
- `AgentService`: creates and lists agents with a single ownership rule.
- `CredentialService`: issues, revokes, delegates, and lists credential metadata with shared ceiling and issuer checks.
- `AuditService`: exports audit records, verifies records, and verifies chains with shared owner/org filtering and safe output rules.
- `IdentityService`: implements `whoami`, `sign`, `discover`, and `challenge` with shared signing, trust topology, challenge, payload-size, and rate-limit behavior.
- `SessionService` remains transport-adjacent: REST creates and rehydrates sessions; mounted MCP reuses existing `x-session`; standalone stdio MCP may use local process/session identity. The shared services receive an already-resolved principal/session context.

Each service should return domain results or normalized domain errors. REST and MCP adapters should only translate those service outcomes into HTTP JSON/status codes or MCP `content`/`isError` responses.

## Shared SQL Validation

SQL query acceptance must have one source of truth. The current MCP-only `extractSingleTable()` helper in `src/mcp/tools.ts` should move into the shared query service or into an approved SQL helper under the library SQL layer. REST `/query` and MCP `query` should both pass through that path.

The shared query path must decide:

- Single-statement and SELECT-only acceptance.
- Whether joins, CTEs, set operations, subqueries, schema-qualified names, and aliases are allowed.
- How the declared `table` parameter is checked against the parsed SQL.
- How `params` are accepted and forwarded.
- How `ScopeEngine` remains the authority for credential scope, projection safety, encrypted-column handling, rejection audit records, and schema-oracle-safe responses.

Do not keep a REST parser and an MCP parser. If parsing is delegated entirely to `ScopeEngine`, remove adapter-level table extraction. If a pre-`ScopeEngine` helper remains necessary, both transports must import the same helper.

## Shared Error Normalization

Introduce a single error normalization function that maps internal errors to a safe domain error object:

```ts
interface NormalizedApiError {
  code: string;
  message: string;
  httpStatus: number;
  safeDetails?: Record<string, unknown>;
}
```

REST should render `httpStatus` and JSON. MCP should render the same `code`, `message`, and safe details inside `content` with `isError: true`; it should not expose HTTP status as part of the MCP contract unless a tool explicitly asks for transport diagnostics.

The normalizer must preserve schema-oracle protections already present in `ScopeViolationError.toSafeResponse()`. It must not expose stack traces, file paths, connection strings, SQL parser internals, key material, or raw unknown error messages. Transport adapters may log internal details server-side, but only safe normalized payloads cross the boundary.

## Shared Rate Limiting

Rate limits belong at the operation/principal level, not inside a transport closure. The current REST server has per-session rate buckets for `sign` and `challenge`; MCP `sign` keeps counters in tool-handler closure state. ABXAGNTS-312 should introduce a shared limiter abstraction used by the identity service.

Recommended key shape:

```ts
type RateLimitKey = {
  operation: 'sign' | 'challenge';
  principalId: string;
  sessionId?: string;
  transport: 'rest' | 'mcp-sse' | 'mcp-stdio';
};
```

For mounted MCP over SSE, use the same `x-session` token identity REST uses. For standalone stdio MCP, key by authenticated human DID plus process instance because there is no HTTP session token. The service should return retry metadata so REST can render `429` and MCP can render `RATE_LIMITED`.

## MCP Dependency Narrowing

`registerTools()` should move away from a broad dependency set that exposes `AgentScope`, `AuthenticatedSession`, and `AuditLogger` directly to every tool. The MCP layer should depend on a narrow service facade, for example:

```ts
interface AgentsApiServices {
  query: QueryService;
  agents: AgentService;
  credentials: CredentialService;
  audit: AuditService;
  identity?: IdentityService;
}
```

MCP may still receive session/principal context at server construction time, but tool handlers should not import `libpg-query`, perform SQL table extraction, reach into `scope.auditLoggerInstance`, or implement their own domain error mapping. That keeps the MCP public contract stable while allowing REST hardening to land behind the same service boundary.

## REST Modularization

`packages/server/src/index.ts` should become a thin bootstrap. ABXAGNTS-313 should split it into focused modules before or alongside broad REST hardening:

- configuration and environment bridging
- app factory and base middleware
- session store and `requireSession`
- normalized error rendering
- route modules by domain
- shared rate limiter construction
- MCP SSE mounting
- storage/revocation/session-store boot wiring
- health/readiness endpoints

This modularization is not cosmetic. Current tests such as `test/server-rest-hardening.test.ts` reimplement inline server logic because the real logic is not importable. The refactor should let tests import real modules and should make route handlers consume the same services as MCP.

## Intentional Transport Differences

The shared boundary does not require REST and MCP to look identical on the wire. These differences are intentional:

- REST creates sessions via `POST /auth/session`; mounted MCP reuses an existing `x-session`; stdio MCP can use local process/session identity.
- REST renders HTTP status codes, headers, OpenAPI schemas, CORS, body-size limits, and JSON responses.
- MCP renders tool results as MCP `content` arrays and signals failures with `isError: true`.
- REST has `/docs`, `/openapi.json`, and HTTP health endpoints; MCP has tools and resources.
- SSE connection setup and `/mcp/messages` routing are transport concerns and should remain in the MCP mount adapter.
- Some transport-level protections, such as CORS and HTTP body limits, are REST-only. Domain protections, such as SQL validation, rate limits, and safe error normalization, are shared.

Do not encode REST URLs, REST status codes, or REST route names as required MCP contract elements. MCP tool names and arguments should stay operation-focused so their implementation can move from direct SDK calls to shared services without breaking callers.

## Implementation Ticket Map

ABXAGNTS-311 should introduce the shared service facade, move active MCP and REST domain paths onto it, and replace or retire `src/mcp/rest-bridge.ts`. It should specifically remove MCP-owned SQL parsing and narrow MCP tool dependencies.

ABXAGNTS-312 should introduce shared validation schemas, shared error normalization, and shared rate limiting. It should cover equivalent REST/MCP query, sign, challenge, and representative error tests.

ABXAGNTS-313 should modularize the REST server so route modules can consume the shared services and tests can import real route/session/rate-limit modules instead of duplicating logic.

ABXAGNTS-314 should build on the shared error and audit rules to harden REST public errors and audit behavior without diverging from MCP.

ABXAGNTS-315 should split liveness/readiness in the modular REST server without affecting shared domain services.

ABXAGNTS-316 should benchmark the query path after the shared service boundary lands and publish the performance envelope for direct MCP, REST, and mounted MCP paths.

ABXAGNTS-252 remains relevant for shared boot logic. If the service factory requires common `AgentScope`/storage/session construction, reuse that spike's inventory rather than adding another boot abstraction.

ABXAGNTS-295 is relevant to packaging. Any new service subpath or internal import path needed by `packages/server` must be covered by CJS and ESM pack smoke tests before publish.

## Consequences

Benefits:

- Query, audit, credential, identity, validation, rate-limit, and error behavior have one implementation path.
- MCP can ship before full REST hardening without freezing a conflicting architecture.
- REST hardening can happen behind the same services MCP already uses.
- Tests can target service behavior once and then assert thin transport rendering separately.

Tradeoffs:

- ABXAGNTS-311 must define a careful service facade before moving handlers.
- The REST bridge stub becomes historical until deliberately rewritten or removed.
- `packages/server` may need a package export or build arrangement to import shared services; ABXAGNTS-295 requires that any such packaging change be smoke-tested in both ESM and CJS.
- Standalone stdio MCP will still need a local session/principal construction path because it does not have REST's HTTP session handshake.

## Verification

This ADR was prepared after reviewing:

- `src/mcp/rest-bridge.ts`
- `test/rest-bridge.test.ts`
- `src/mcp/tools.ts`
- `packages/server/src/index.ts`
- `packages/server/src/openapi.ts`
- `test/server-rest-hardening.test.ts`
- `test/rest-hardening.test.ts`
- Jira tickets ABXAGNTS-252, ABXAGNTS-295, ABXAGNTS-310, ABXAGNTS-311, ABXAGNTS-312, ABXAGNTS-313, ABXAGNTS-314, ABXAGNTS-315, and ABXAGNTS-316
