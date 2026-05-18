# Agents++ Smoke Test App

This app is a consumer-facing test harness for `@abaxxtech/agents`. It exists to
catch integration regressions that unit tests can miss: package subpath exports,
local file dependency resolution, Postgres schema setup, `AgentScope` query
scoping, column encryption, overscope rejection, and audit/status reporting.

## Database

The app needs a live Postgres database. Treat the selected database as
disposable test infrastructure: each run drops and recreates the Agents++
infrastructure tables plus the app's order table. This is intentional because
`AgentScope` restores all persisted agents at boot, and stale rows encrypted
under another master key should not make a clean consumer smoke test flaky.

By default it uses the repo demo stack:

```bash
cd ../../demo
docker compose up -d postgres
```

That exposes Postgres at:

```bash
postgresql://postgres:postgres@localhost:5433/postgres
```

Override with `DATABASE_URL` when testing another database:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:54322/postgres npm test
```

Do not point `DATABASE_URL` at a database that contains data you need to keep.

## Run

```bash
npm install
npm test
npm run smoke
npm run web
```

`npm test` runs the Vitest assertion wrapper. `npm run smoke` prints a compact
human-readable result for manual checks. `npm run web` starts a small browser
harness at `http://localhost:3210` with a button that runs the same smoke flow
and renders the result.

The scripts build the parent package first because this app imports
`@abaxxtech/agents` through the published `dist` exports, matching a real
consumer install.
