# Steward Local Mode — Revised MVP Plan

> **Status:** Revised after dual-model audit (GPT 5.4 + Opus 4.6)  
> **Date:** 2026-03-23  
> **Supersedes:** LOCAL_AGENT_PLAN.md (1366-line original was overengineered)

---

## What Both Reviewers Agreed On

The original plan is well-designed but massively overscoped. Key findings:

1. **The SQLite rewrite is the biggest hidden blocker.** The entire `@stwd/db` package is hardcoded to Postgres (`pgEnum`, `pgTable`, `jsonb`, Postgres-specific SQL). Porting to SQLite would require a parallel schema, new client, different migration system, and testing every query against SQLite's limitations (no native jsonb, no enums, different timestamp handling). This alone is 1-2 weeks.

2. **Sidecar is the right architecture, but not for MVP.** For MVP, just run the full Steward API as a sidecar (same binary, same Postgres, pointed at a local DB). The in-process vault approach is faster to ship but loses process isolation.

3. **The "local identity" subsystem is unnecessary.** The existing tenant + agent model works fine. Create a local tenant, create one agent, done. No need for a parallel identity system.

4. **SIWE / wallet-as-identity is a separate project.** It requires changes in Eliza Cloud (a different repo), not just Steward. Don't block local mode on it.

5. **Cross-platform keychain integration is a rabbit hole.** File-based master password with 0600 permissions is fine for MVP. Keychain is a polish item.

---

## Revised Architecture: Keep It Simple

```
┌──────────────────────────────────────┐
│  Milady Desktop App (Electrobun)     │
│                                      │
│  AgentManager spawns:                │
│    1. ElizaOS runtime (existing)     │
│    2. Steward API (NEW sidecar)      │
│         └─ same binary as cloud      │
│         └─ PGLite instead of Postgres│
│         └─ port 7860                 │
│                                      │
│  @stwd/eliza-plugin connects to      │
│  http://127.0.0.1:7860 (same as     │
│  cloud mode, just different URL)     │
└──────────────────────────────────────┘
```

**Key insight from both reviewers:** Don't build a "local mode" — build the same Steward, running locally. The plugin doesn't need to know or care.

### Why PGLite, Not SQLite

Both reviewers flagged the SQLite port as the biggest risk. PGLite (Postgres compiled to WASM, runs in Bun/Node) solves this:

- **Same schema, same queries, same migrations.** Zero changes to `@stwd/db`.
- `npm install @electric-sql/pglite` — single dependency
- Stores data in a local directory (`~/.config/Milady/steward/pgdata/`)
- Drizzle ORM supports PGLite natively via `drizzle-orm/pglite`
- No need for a system Postgres install

The ONLY code change is in `packages/db/src/client.ts`: swap `postgres()` for `PGlite()` when `STEWARD_LOCAL_MODE=true`.

---

## MVP Scope (1 Week)

### What We Build

**1. PGLite database adapter** (0.5 day)
- Add `@electric-sql/pglite` dependency to `@stwd/db`
- Modify `client.ts`: if `STEWARD_LOCAL_MODE=true`, use PGLite with file path instead of Postgres URL
- Run existing migrations against PGLite on first start
- Zero schema changes

**2. Embedded entry point** (0.5 day)
- New file: `packages/api/src/embedded-entry.ts`
- Imports the existing Hono app
- Sets env vars: `STEWARD_LOCAL_MODE=true`, generates master password if missing, binds to `127.0.0.1:7860`
- Auto-creates a `local` tenant and one agent on first start
- Skips auth for localhost requests (or auto-generates a local API key)

**3. StewardSidecar module in Milady desktop** (1 day)
- New file: `apps/app/electrobun/src/native/steward-sidecar.ts`
- Follows exact same pattern as existing `AgentManager` (Bun.spawn, health poll, lifecycle)
- Spawns Steward embedded entry as child process
- Passes env vars: data dir, master password, port
- `AgentManager.start()` calls `StewardSidecar.start()` first, injects `STEWARD_API_URL` into agent env

**4. Auto-provision on first launch** (0.5 day)
- Steward embedded entry detects empty DB on startup
- Creates local tenant + agent + default policies
- Generates EVM + Solana keypairs
- Saves agent token to a file for the eliza-plugin to read

**5. Plugin wiring** (0.5 day)
- `@stwd/eliza-plugin` already supports `STEWARD_API_URL` env var
- Sidecar injects `STEWARD_API_URL=http://127.0.0.1:7860` + `STEWARD_AGENT_TOKEN` into agent process
- Plugin connects on startup, same as cloud mode
- No plugin code changes needed if bearer token auth works

**6. Master password management** (0.5 day)
- On first launch: generate 32-byte random hex, save to `~/.config/Milady/steward/.master` with `0600` permissions
- On subsequent launches: read from file
- Document: "keychain integration planned for future release"

**7. Build + bundle** (1 day)
- Add `build:embedded` script to steward-fi: `bun build packages/api/src/embedded-entry.ts --target bun --outdir dist/embedded`
- Add copy step to Milady desktop build scripts
- Test the full flow: app launch → sidecar starts → agent connects → signing works

### What We Defer

| Item | Reason | When |
|------|--------|------|
| SQLite support | PGLite eliminates the need | Never (unless PGLite has issues) |
| SIWE / wallet-as-identity | Requires Eliza Cloud changes, separate workstream | Phase 2 (2-3 weeks) |
| Settings UI for policies | Agent works with defaults, users don't need to configure day 1 | Phase 2 |
| Backup / recovery | Power user feature, not MVP | Phase 3 |
| Cross-platform keychain | File-based is fine for now | Phase 3 |
| Policy presets UI | Defaults work, custom config is power-user | Phase 3 |
| Multi-device sync | Manual export/import first | Phase 4 |
| Separate local identity system | Use existing tenant/agent model | Cut entirely |
| Independent Steward updates | Users update the whole app | Cut entirely |
| Recovery phrase export | Requires mnemonic-based derivation (we use random keys) | Cut entirely unless we switch to HD wallets |

### What We Cut Entirely

1. **Separate `local_identity` table/subsystem** — The existing agent model works. One tenant, one agent, done.
2. **`mode: 'embedded'` in the SDK** — Not needed. SDK talks HTTP to `localhost:7860`, same as cloud.
3. **In-process vault (no HTTP)** — More work than sidecar for marginal benefit. The HTTP overhead on localhost is <1ms.
4. **Recovery phrase display** — We generate random keys, not from mnemonics. Can't show a recovery phrase without switching to HD wallet derivation. If we need backup, use encrypted file export.

---

## Implementation Details

### PGLite Adapter (`packages/db/src/client.ts`)

```typescript
import { drizzle as drizzlePg } from "drizzle-orm/postgres-js";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import postgres from "postgres";
import { PGlite } from "@electric-sql/pglite";
import * as schema from "./schema";

let db: ReturnType<typeof drizzlePg> | ReturnType<typeof drizzlePglite>;

export function getDb() {
  if (db) return db;

  if (process.env.STEWARD_LOCAL_MODE === "true") {
    const dataDir = process.env.STEWARD_DB_PATH || "./steward-data";
    const client = new PGlite(dataDir);
    db = drizzlePglite(client, { schema });
  } else {
    const connectionString = getDatabaseUrl();
    const client = postgres(connectionString);
    db = drizzlePg(client, { schema });
  }

  return db;
}
```

### Embedded Entry (`packages/api/src/embedded-entry.ts`)

```typescript
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// Set local mode before anything imports the DB
process.env.STEWARD_LOCAL_MODE = "true";
process.env.STEWARD_DB_PATH = process.env.STEWARD_DB_PATH
  || path.join(process.env.STEWARD_DATA_DIR || ".", "pgdata");

// Master password
const dataDir = process.env.STEWARD_DATA_DIR || ".";
const masterFile = path.join(dataDir, ".master");
if (!process.env.STEWARD_MASTER_PASSWORD) {
  if (fs.existsSync(masterFile)) {
    process.env.STEWARD_MASTER_PASSWORD = fs.readFileSync(masterFile, "utf8").trim();
  } else {
    const pw = crypto.randomBytes(32).toString("hex");
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(masterFile, pw, { mode: 0o600 });
    process.env.STEWARD_MASTER_PASSWORD = pw;
  }
}

process.env.PORT = process.env.STEWARD_PORT || "7860";
process.env.STEWARD_BIND_HOST = "127.0.0.1";

// Import and start the API (runs migrations, starts server)
import "./index.ts";

// Auto-provision local agent after server starts
// (handled in a startup hook inside index.ts when LOCAL_MODE is detected)
```

### StewardSidecar (Milady desktop)

```typescript
// apps/app/electrobun/src/native/steward-sidecar.ts
// Follows exact pattern of agent.ts AgentManager

export class StewardSidecar {
  private process: BunSubprocess | null = null;

  async start(dataDir: string): Promise<{ port: number; token: string }> {
    const stewardEntry = resolveStewardEntry(); // bundled dist
    const port = 7860;

    this.process = Bun.spawn(
      [resolveBunPath(), "run", stewardEntry],
      {
        env: {
          ...process.env,
          STEWARD_DATA_DIR: dataDir,
          STEWARD_PORT: String(port),
          STEWARD_LOCAL_MODE: "true",
        },
        stdout: "pipe",
        stderr: "pipe",
      }
    );

    await this.waitForHealth(port);

    // Read the auto-generated agent token
    const tokenFile = path.join(dataDir, "agent-token.txt");
    const token = fs.readFileSync(tokenFile, "utf8").trim();

    return { port, token };
  }

  async stop() { /* SIGTERM, wait, SIGKILL if needed */ }

  private async waitForHealth(port: number) {
    // Same pattern as AgentManager.waitForHealth
  }
}
```

### Integration in AgentManager

```typescript
// In AgentManager.start(), before spawning agent:
const steward = getStewardSidecar();
const { port, token } = await steward.start(stewardDataDir);

// Inject into agent env
childEnv.STEWARD_API_URL = `http://127.0.0.1:${port}`;
childEnv.STEWARD_AGENT_TOKEN = token;
```

---

## Dependency Order

```
Week 1:
  Day 1-2: PGLite adapter + embedded-entry.ts (Steward repo)
  Day 3:   Auto-provision logic (Steward repo)
  Day 4:   StewardSidecar module (Milady repo)
  Day 5:   Build pipeline + integration test

Week 2 (if needed):
  - Polish, edge cases, error handling
  - Test on macOS + Windows
```

Steward work blocks Milady work. PGLite adapter must land first, then embedded entry, then the Milady-side sidecar can integrate.

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| PGLite compatibility with Drizzle | Low | High | PGLite is explicitly supported by Drizzle. Test with `bun test` against PGLite before shipping |
| PGLite performance | Low | Medium | It's local, single-user. Performance is fine |
| Bun.spawn on Windows | Medium | Medium | Test early. Windows path resolution and process management differ |
| Master password file security on multi-user Linux | Low | Medium | File permissions 0600. Document recommendation for full-disk encryption |
| Large bundle size (viem + solana + drizzle + pglite) | Medium | Low | Tree-shake on build. PGLite WASM is ~5MB |

---

## Success Criteria

MVP is done when:
1. Desktop app launches → Steward sidecar starts automatically
2. Agent connects to Steward on localhost
3. Agent can sign a transaction through Steward with policy enforcement
4. Wallet persists across app restarts (PGLite on disk)
5. No manual setup required (auto-provision on first launch)

---

*This plan replaces the 1366-line original with a focused 1-week MVP that reuses existing code and avoids the SQLite rewrite trap.*
