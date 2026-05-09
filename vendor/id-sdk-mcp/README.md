# id-sdk MCP server

This MCP server exposes a small set of tools around `IDDwn`, loaded from this
folder's built output in `sdk/esm`.

## Agents++ vendoring note

This copy is vendored into `@abaxxlabs/agents` so deployments can use the
platform id-sdk through an MCP process boundary instead of importing an
in-process SDK package. That boundary keeps private key/session state inside
the server process.

The vendored `server.mjs` includes Agents++ compatibility tools beyond the
original platform copy:

- `vc_get_signer_options`
- `vc_verify_jwt`
- `vc_decode_jwt`
- `vc_parse_jwt`
- `vc_create_revocable_credential`
- `vc_revoke_credential`
- `vc_check_credential_status`

Preserve those tools when re-syncing from the platform package unless upstream
has equivalent coverage.

## Dependencies

Runtime dependencies are declared in the root `@abaxxlabs/agents/package.json`,
not here. `npm install @abaxxlabs/agents` brings everything `server.mjs` needs.

`level` and `@mattrglobal/bbs-signatures` are listed under
`optionalDependencies` so the main package install still succeeds on platforms
where their native build steps fail (Alpine, uncommon ARM, etc.). On those
platforms the MCP server fails fast with a clear error pointing at the missing
dep instead of bringing the whole package install down.

When syncing this folder from the upstream id-sdk repo, also reconcile
`vendor/id-sdk-mcp`'s dependency list with the matching pins in the root
`package.json`.

## Requirements

- Build output exists at `sdk/esm`.
- Node.js 20.3+.

## Run

Production callers use `connectIdSdkMcp()` from
`@abaxxlabs/agents/id-sdk-mcp`, which spawns this server over stdio.

For local debugging the server can be started directly:

```bash
node vendor/id-sdk-mcp/server.mjs
```

## Available tools

- `connect`
- `session_status`
- `did_create`
- `did_resolve`
- `vc_create_credential`
- `vc_sign_credential`
- `vc_get_signer_options`
- `vc_verify_jwt`
- `vc_decode_jwt`
- `vc_parse_jwt`
- `vc_create_revocable_credential`
- `vc_revoke_credential`
- `vc_check_credential_status`
- `vp_create_presentation`
- `vp_decode_presentation`
- `dwn_records_write`
- `dwn_records_query`
- `dwn_records_read`
- `dwn_records_delete`
- `flush_outbox_and_sync`

Use `connect` first. Other tools require an active in-process session.

## MCP Inspector

```bash
npx @modelcontextprotocol/inspector node vendor/id-sdk-mcp/server.mjs
```
