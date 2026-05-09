# Agents++ Test Apps

Small consumer-style applications live here. They are intentionally outside the
library `src/` and `test/` trees so they exercise Agents++ the way an adopter
would: through package subpath exports, a real package install, and a live
database boundary.

Current apps:

- `agents-plus-smoke` — a Postgres-backed smoke app that creates two agents,
  issues scoped credentials, runs allowed queries, blocks an overscope query,
  and checks audit/status output.
