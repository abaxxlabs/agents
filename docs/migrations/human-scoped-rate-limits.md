# Migration: human-scoped rate limits

**Audience:** anyone embedding `createMcpServer()` or `registerTools()` from `@abaxxlabs/agents`.

MCP rate limits were keyed by `parentIssuerDid`, so every human in one organization shared a bucket. Quotas are now keyed by `humanDid`, and credential issuance and delegation draw on one shared quota.

---

## TL;DR

Two things can break you:

1. If you pass `rateLimitPrincipal` to `createMcpServer()` or `registerTools()`, delete that property. It no longer exists.
2. If you mint more than 100 credentials per minute per human through MCP, that traffic now fails with `RATE_LIMITED`. It was previously unlimited.

Everything else is a tightening of existing limits, not an API change.

---

## 1. `rateLimitPrincipal` is gone

```ts
// before
const server = createMcpServer({
  scope,
  session,
  auditLogger,
  rateLimiter,
  rateLimitPrincipal: sessionToken, // ← remove this line
});

// after
const server = createMcpServer({
  scope,
  session,
  auditLogger,
  rateLimiter,
});
```

The property allowed callers to replace the human identity used as the quota principal. The principal is now always `session.humanDid`, with no override.

TypeScript will flag the removed property as an excess property. There is no runtime fallback that silently ignores it.

## 2. MCP credential tools share one limit

`issue-credential` and `delegate-credential` previously had no rate limit. They now share one quota:

| Surface | Before | After |
|---|---|---|
| MCP `issue-credential` | unlimited | 100/min per human, shared |
| MCP `delegate-credential` | unlimited | 100/min per human, shared |

Shared means one bucket: 60 issuances plus 41 delegations in the same minute is 101 operations, and the last one is rejected.

**If you run bulk provisioning** (seeding, batch onboarding, migrations) that mints more than 100 credentials per minute for one human, it will now fail partway through with `RATE_LIMITED`. Options, in order of preference:

- Spread the work across the quota window, or across multiple human identities if the provisioning is genuinely on behalf of different people.
- Inject your own `RateLimiter` implementation with limits appropriate to your deployment. `createMcpServer({ rateLimiter })` accepts any object satisfying the `RateLimiter` interface, so a permissive limiter for a trusted batch process is a few lines.

Note that a consumer calling `createMcpServer()` without injecting a `rateLimiter` shares the process-wide `defaultIdentityRateLimiter` singleton. That was already true for `sign` and `challenge`; it now also applies to credential minting.

## 3. Sign and challenge quotas no longer multiply per session

The limits themselves are unchanged (100/min for sign, 30/min for challenge), but they now count per human rather than per session token. A user holding three concurrent sessions previously had an effective 300 signs per minute. They now have 100 in total.

No code change is required. Expect support reports from users who relied on the old effective ceiling.

On the other side of the ledger, MCP previously keyed by `parentIssuerDid`, so every human in one organization shared a single bucket and one user could exhaust the quota for all of their colleagues. That is fixed by the same change.

## 4. Rejection shape is unchanged

MCP tools return `isError: true` with `error`, `message`, and `retryAfterSeconds`. Clients calling `issue-credential` or `delegate-credential` must handle `RATE_LIMITED` responses.

## 5. What did not change

Quotas remain in-memory and per process. Each replica keeps its own counters, and a restart clears them. Distributed rate limiting is out of scope for this change, so a deployment with N replicas still has an effective ceiling of N times the configured limit unless the load balancer pins a human to one instance.
