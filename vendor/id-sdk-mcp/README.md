# id-sdk MCP server

This MCP server exposes a small set of tools around `IDDwn`, loaded from this repo's built output in `sdk/esm`.

## Agents++ vendoring note

This copy is vendored into `@abaxxlabs/agents` so deployments can use the
platform id-sdk through an MCP process boundary instead of importing an
in-process SDK package. That boundary keeps private key/session state inside the
server process and keeps the Agents++ package lightweight.

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

## Requirements

- Build output exists at `sdk/esm` (run `bun run build` at id-sdk repo to update).
- Node.js 20.3+.

## Install

```bash
cd packages/id-sdk-mcp
bun install
```

## Run

```bash
bun run start
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

## Run MCP Inspector

```bash
  bunx @modelcontextprotocol/inspector node server.mjs
```
