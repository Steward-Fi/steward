# @stwd/redis

Private Steward workspace package for Redis-backed rate limiting, spend
reservation and settlement, cumulative spend windows, policy caching, and cost
estimation.

The package supports ioredis-compatible clients and an Upstash adapter. Server
packages should consume its exported operations rather than issue ad hoc Redis
commands so atomic reservation and fail-closed behavior remain centralized.

## Validation

```bash
bun run build
bun test
```

This package is private and is not published independently.
