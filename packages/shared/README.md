# @stwd/shared

Shared domain types, constants, validation helpers, and execution contracts used
by Steward packages.

```ts
import type { AgentIdentity, PolicyRule } from "@stwd/shared";
import { CHAIN_PROVIDERS } from "@stwd/shared/client";
import { SENSITIVE_KEY_PATTERNS } from "@stwd/shared/sensitive-keys";
```

Exports are split into three entry points:

- `@stwd/shared` — server and package-level domain contracts;
- `@stwd/shared/client` — browser-safe chain and display helpers; and
- `@stwd/shared/sensitive-keys` — sensitive-key classification helpers.

Keep runtime-specific dependencies out of this package. New shared contracts
should have a concrete consumer in more than one package; package-local types
belong with their implementation.

## Validation

```bash
bun run build
bun test
```

## License

MIT
