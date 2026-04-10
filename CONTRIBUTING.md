# Contributing to Steward

Thanks for your interest in contributing to Steward! This guide will help you get set up and submit your first PR.

## Prerequisites

- [Bun](https://bun.sh) 1.3+
- Git

## Dev Setup

```bash
# Clone the repo
git clone https://github.com/Steward-Fi/steward.git
cd steward

# Install dependencies
bun install

# Run the API server locally
bun run packages/api/src/index.ts
```

## Project Structure

Steward is a monorepo managed with [Turborepo](https://turbo.build). All packages live under `packages/`:

| Package | Description |
|---------|-------------|
| `api` | Core REST API server (Hono) |
| `auth` | Authentication service (passkeys, OAuth, email) |
| `db` | Database schemas and migrations (Drizzle + Postgres) |
| `policy-engine` | Transaction policy rules and evaluation |
| `proxy` | RPC proxy with policy enforcement |
| `redis` | Redis client and caching layer |
| `shared` | Shared types, utils, and constants |
| `sdk` | Client SDK (`@stwd/sdk`) |
| `vault` | Key management and signing |
| `webhooks` | Webhook delivery and management |
| `react` | React auth components (`@stwd/react`) |
| `eliza-plugin` | ElizaOS plugin for agent wallets |
| `agent-trader` | Autonomous agent trading module |
| `seed` | Database seeding scripts |
| `examples` | Example integrations |

## Making Changes

### 1. Branch from develop

```bash
git checkout develop
git pull origin develop
git checkout -b feat/my-feature
```

Branch naming: `feat/`, `fix/`, `docs/`, `chore/`, `refactor/`, `test/`

### 2. Write your code

- TypeScript strict mode, no `any` types
- Add tests for new features (`bun test` in the relevant package)
- React components use BEM CSS with `stwd-` prefix

### 3. Commit with conventional commits

Format: `type(scope): description`

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`

Examples:
```
feat(sdk): add batch transaction support
fix(auth): handle expired OAuth tokens
docs(readme): update quickstart section
chore(ci): add docker build workflow
```

### 4. Include the co-author line

All commits must include:
```
Co-authored-by: wakesync <shadow@shad0w.xyz>
```

Add it with:
```bash
git commit -m "feat(sdk): add batch support" -m "" -m "Co-authored-by: wakesync <shadow@shad0w.xyz>"
```

### 5. Open a PR

- Target branch: `develop` (not `main`)
- Fill out the PR template completely
- Make sure CI passes
- Request review from `@0xSolace`

## Testing

Run tests in any package:

```bash
cd packages/api
bun test
```

Or run all tests from the root:

```bash
bun test
```

## Code Style

- **TypeScript strict** across all packages
- **No `any` types** unless absolutely necessary (and documented why)
- **Imports:** use `@stwd/shared` for shared types, not relative paths across packages
- **React:** BEM CSS naming with `stwd-` prefix (e.g., `stwd-login__button--active`)
- **Error handling:** throw typed errors, don't swallow silently

## Need Help?

- Open an issue if something is unclear
- Check existing issues and PRs for context
- Reach out in the [Steward Discord](https://discord.gg/steward)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
