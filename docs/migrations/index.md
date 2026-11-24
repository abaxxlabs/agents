---
id: source-migrations
title: Source migrations
description: Historical repository-source integration changes and migration guides.
slug: /migrations
---

# Source migrations

These guides are for application maintainers adapting an existing Agents++ integration to changes in key handling, package imports, rate limits, or credential claims. Start with the guide that matches the API or behavior your application uses; the [BYOK guide](byok.md) covers explicit master-key injection and durable revocation storage.

Historical version labels in these guides identify repository-source releases, not public npm upgrade targets. In particular, the [BYOK rollback procedure](v0.9.10-rollback.md) requires a retained source build because v0.9.10.0 and v0.9.9.x were not published to the public npm registry. For a new integration, start with [Installation](../guides/installation.md) and [Quick start](../guides/quick-start.md).

## Guides

- [BYOK master key and injections boundary](byok.md)
- [BYOK rollback procedure](v0.9.10-rollback.md)
- [Package subpath exports: v0.10 to v0.11](v0.11.md)
- [Human-scoped rate limits](human-scoped-rate-limits.md)
- [VC-JWT delegation claim placement](vc-jwt-claim-placement.md)
