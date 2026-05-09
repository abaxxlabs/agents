# ADR — MCP HTTP transport session model

## Status

Accepted ([internal ref], audit closeout for HIGH-3 from the v0.5.0 white-box audit).

## Context

The MCP HTTP transport in `src/mcp/index.ts` previously stored a single closure-scoped `SSEServerTransport` reference. Every `GET /sse` overwrote the variable; every `POST /messages` routed to whichever client connected last. This produced cross-client message routing, broke JSON-RPC request/response correlation, and let any reconnecting bearer holder silently hijack other clients (CWE-384, CWE-863).

Two related but distinct questions were folded together in the audit: how should concurrent SSE channels be routed, and how many human identities can a single MCP process serve.

## Decision

The MCP HTTP transport tracks SSE clients via a `Map<sessionId, SSEServerTransport>` keyed by the SDK-generated UUID surfaced in each transport's `endpoint` event. Posts on `/messages?sessionId=<uuid>` are routed to the named transport only. Missing or unknown session IDs return `400 invalid_session`. Lifetime is bounded by the underlying SSE response: when the response emits `close`, the map entry is deleted.

The MCP server remains single-human-DID per process. The boot-time `scope.authenticate(...)` at `src/mcp/index.ts:142-148` establishes one human session, and every bearer-authenticated SSE connection operates under that human's authority. Multiple concurrent SSE connections are permitted (e.g. one human running a CLI client and an IDE client simultaneously) and are routed independently. To run as a different human, restart the process with a different identity.

A `singleSessionMode` config flag on `McpHttpHandlerOptions` is available for consumers that require strict single-connection-per-process enforcement: a second `GET /sse` while one session is open returns `409 Conflict`. It is opt-in and defaults to `false`; `startMcpServer` does not enable it. Consumers that need it (e.g. a strictly embedded single-client deployment) can pass `singleSessionMode: true` explicitly.

## Consequences

Routing is correct under concurrent clients and during bearer token rotation overlap. Cross-session message leakage is no longer reachable. Memory under load is bounded by the OS / proxy `close` semantics on long-idle SSE responses. The handler is extracted into `src/mcp/http-handler.ts` so the routing logic is unit-testable without booting an `http.Server`. The bearer-auth posture is unchanged by this decision; HIGH-4 (`fail closed when bearer auth is absent`) is tracked separately as [internal ref].

A consumer that mixes MCP clients across multiple humans must run multiple MCP processes. There is no in-process tenancy boundary other than the bearer token itself, and the bearer token's authority is bound to the boot-time human.
