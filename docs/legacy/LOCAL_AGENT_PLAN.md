# Steward Integration Plan: Local/Desktop Agents (Track B)

> **Status:** Draft  
> **Author:** Sol (automated planning)  
> **Date:** 2026-03-22  
> **Related docs:**  
> - `DOCKER_AGENT_INTEGRATION.md` — Track A (cloud containers)  
> - `ELIZA_PLUGIN_DESIGN.md` — Eliza plugin architecture  
> - `REPLACE_PRIVY_PLAN.md` — Cloud auth migration  

---

## Executive Summary

This document defines how Steward integrates with **local agents** — the desktop app (Electrobun) and CLI users who run agents on their own machines. Unlike cloud containers (Track A), local agents:

1. **Own their hardware** — users control the machine, so policies can be more permissive
2. **Need embedded Steward** — no external API dependency, Steward runs locally
3. **Use wallet-as-identity** — the auto-generated wallet IS the user's identity for Eliza Cloud
4. **Bootstrap automatically** — first launch generates wallets, no separate key management

### Current State

The `@stwd/eliza-plugin` already has local fallback built in:
- Auto-discovers Steward at `localhost:7860`
- Falls back to local signing if Steward isn't running
- `STEWARD_FALLBACK_LOCAL=true` by default

What's missing for a complete local experience:
- Embedded Steward bundled with the desktop app
- Auto-wallet generation on first launch
- Wallet-as-identity for cloud registration
- Permissive local-first policy defaults
- Settings UI for policy management

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Embedded Steward Mode](#2-embedded-steward-mode)
3. [Auto-Generate Wallets on First Launch](#3-auto-generate-wallets-on-first-launch)
4. [Wallet-as-Identity](#4-wallet-as-identity)
5. [Policy Defaults for Local Agents](#5-policy-defaults-for-local-agents)
6. [Settings Integration](#6-settings-integration)
7. [Implementation Phases](#7-implementation-phases)
8. [Security Considerations](#8-security-considerations)
9. [Open Questions](#9-open-questions)

---

## 1. Architecture Overview

### Local Agent Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Electrobun Desktop App                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Main Process (Bun)                                           │   │
│  │   ├── AgentManager (spawns agent runtime)                    │   │
│  │   ├── StewardSidecar (NEW: spawns embedded Steward)          │   │
│  │   └── Native modules (desktop, permissions, etc.)            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────┼─────────────────────────────────┐   │
│  │ Agent Runtime (child Bun process)                            │   │
│  │   ├── ElizaOS core                                           │   │
│  │   ├── @stwd/eliza-plugin ─────────┐                          │   │
│  │   └── Other plugins               │                          │   │
│  └───────────────────────────────────┼─────────────────────────┘   │
│                                      │                              │
│  ┌───────────────────────────────────▼─────────────────────────┐   │
│  │ Embedded Steward (NEW: sidecar process)                      │   │
│  │   ├── Vault (encrypted keystore)                             │   │
│  │   ├── Policy Engine                                          │   │
│  │   ├── SQLite/PGLite DB (local file)                          │   │
│  │   └── RPC signing (EVM + Solana)                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Differences from Cloud (Track A)

| Aspect | Cloud Containers (Track A) | Local Desktop (Track B) |
|--------|---------------------------|------------------------|
| **Steward location** | Per-node service, shared by containers | Embedded sidecar per app instance |
| **Database** | Shared Neon PostgreSQL | Local SQLite file |
| **Trust model** | Platform controls keys | User controls keys |
| **Policy defaults** | Conservative (0.1 ETH limits) | Permissive (user's machine) |
| **Identity** | Platform-assigned agentId | Wallet address IS identity |
| **Key visibility** | Never visible to user | Optional export/backup |

---

## 2. Embedded Steward Mode

### 2.1 Sidecar vs Built-In

**Recommendation: Sidecar process** (separate Bun process)

**Why sidecar:**
- Clean process isolation (vault crash doesn't kill UI)
- Same architecture as cloud (Steward is always a separate service)
- Easier to update Steward independently
- Memory isolation for secrets
- Can run on different port from agent API

**Why NOT built-in (shared process):**
- If agent crashes, vault state may be corrupted
- Mixing agent runtime dependencies with Steward dependencies
- Harder to reason about security boundaries

### 2.2 Implementation: StewardSidecar Module

New file: `apps/app/electrobun/src/native/steward-sidecar.ts`

```typescript
/**
 * StewardSidecar — Manages the embedded Steward process lifecycle.
 *
 * Spawns Steward API as a child process (Bun), manages startup/shutdown,
 * and provides health checks. The sidecar stores its vault DB in the
 * platform-appropriate config directory (~/.config/Milady or %APPDATA%/Milady).
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const STEWARD_PORT = 7860;
const HEALTH_POLL_MS = 500;
const STARTUP_TIMEOUT_MS = 15_000;

interface StewardSidecarStatus {
  state: "not_started" | "starting" | "running" | "stopped" | "error";
  port: number | null;
  walletAddress: string | null;
  error: string | null;
}

export class StewardSidecar {
  private process: ReturnType<typeof Bun.spawn> | null = null;
  private status: StewardSidecarStatus = {
    state: "not_started",
    port: null,
    walletAddress: null,
    error: null,
  };

  /**
   * Resolve paths for embedded Steward:
   *   - stewardDist: The bundled Steward API entry
   *   - dataDir: Where vault DB lives (~/.config/Milady/steward)
   *   - vaultFile: The encrypted vault SQLite file
   */
  private resolvePaths() {
    const configDir = process.platform === "win32"
      ? path.join(process.env.APPDATA ?? path.join(os.homedir(), "AppData/Roaming"), "Milady")
      : path.join(os.homedir(), ".config/Milady");
    
    const dataDir = path.join(configDir, "steward");
    const vaultFile = path.join(dataDir, "vault.sqlite");
    
    // Steward entry bundled alongside agent runtime
    const miladyDistPath = resolveMiladyDistPath(); // reuse from agent.ts
    const stewardEntry = path.join(miladyDistPath, "steward", "entry.js");
    
    return { configDir, dataDir, vaultFile, stewardEntry };
  }

  /**
   * Start the embedded Steward sidecar.
   * 
   * First launch flow:
   * 1. Create data directory if missing
   * 2. Generate machine-specific master password (or use existing)
   * 3. Spawn Steward API process
   * 4. Wait for health check
   * 5. If no wallets exist, trigger auto-provisioning
   */
  async start(): Promise<StewardSidecarStatus> {
    if (this.status.state === "running" || this.status.state === "starting") {
      return this.status;
    }

    const paths = this.resolvePaths();
    
    // Ensure data directory exists
    if (!fs.existsSync(paths.dataDir)) {
      fs.mkdirSync(paths.dataDir, { recursive: true, mode: 0o700 });
    }

    // Check if Steward entry exists
    if (!fs.existsSync(paths.stewardEntry)) {
      this.status = {
        state: "error",
        port: null,
        walletAddress: null,
        error: `Steward not bundled at ${paths.stewardEntry}`,
      };
      return this.status;
    }

    this.status = { state: "starting", port: STEWARD_PORT, walletAddress: null, error: null };

    // Get or generate master password
    const masterPassword = await this.getOrCreateMasterPassword(paths.dataDir);

    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
      STEWARD_PORT: String(STEWARD_PORT),
      STEWARD_MASTER_PASSWORD: masterPassword,
      STEWARD_DB_PATH: paths.vaultFile,
      STEWARD_LOCAL_MODE: "true",  // Enables local-only features
      STEWARD_AUTO_PROVISION: "true", // Auto-create wallet on first request
    };

    const bunExecutable = resolveBunExecutablePath();
    
    this.process = Bun.spawn(
      [bunExecutable, "run", paths.stewardEntry],
      {
        cwd: path.dirname(paths.stewardEntry),
        env,
        stdout: "pipe",
        stderr: "pipe",
      }
    );

    // Wait for health
    const healthy = await this.waitForHealthy();
    
    if (!healthy) {
      this.status = {
        state: "error",
        port: STEWARD_PORT,
        walletAddress: null,
        error: "Steward failed to start within timeout",
      };
      await this.stop();
      return this.status;
    }

    // Fetch wallet address (may be null on first run before provisioning)
    const walletAddress = await this.fetchWalletAddress();

    this.status = {
      state: "running",
      port: STEWARD_PORT,
      walletAddress,
      error: null,
    };

    return this.status;
  }

  async stop(): Promise<void> {
    if (!this.process) return;
    
    this.process.kill("SIGTERM");
    await Promise.race([
      this.process.exited,
      Bun.sleep(5_000),
    ]);
    
    if (this.process.exitCode === null) {
      this.process.kill("SIGKILL");
    }
    
    this.process = null;
    this.status = { state: "stopped", port: null, walletAddress: null, error: null };
  }

  private async waitForHealthy(): Promise<boolean> {
    const deadline = Date.now() + STARTUP_TIMEOUT_MS;
    
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://127.0.0.1:${STEWARD_PORT}/health`, {
          signal: AbortSignal.timeout(2_000),
        });
        if (res.ok) return true;
      } catch {
        // Not ready yet
      }
      await Bun.sleep(HEALTH_POLL_MS);
    }
    
    return false;
  }

  private async fetchWalletAddress(): Promise<string | null> {
    try {
      const res = await fetch(`http://127.0.0.1:${STEWARD_PORT}/local/identity`);
      if (res.ok) {
        const data = await res.json() as { walletAddress?: string };
        return data.walletAddress ?? null;
      }
    } catch {
      // No wallet provisioned yet
    }
    return null;
  }

  /**
   * Machine-specific master password, derived from hardware identifiers.
   * Stored encrypted in keychain (macOS) or credential manager (Windows).
   * Falls back to a file-based approach on Linux.
   */
  private async getOrCreateMasterPassword(dataDir: string): Promise<string> {
    const secretFile = path.join(dataDir, ".master");
    
    // TODO: Use platform keychain APIs instead of file
    // - macOS: Keychain Services
    // - Windows: Credential Manager
    // - Linux: libsecret / GNOME Keyring
    
    if (fs.existsSync(secretFile)) {
      return fs.readFileSync(secretFile, "utf8").trim();
    }
    
    // Generate new master password
    const crypto = await import("node:crypto");
    const password = crypto.randomBytes(32).toString("hex");
    
    fs.writeFileSync(secretFile, password, { mode: 0o600 });
    
    return password;
  }

  getStatus(): StewardSidecarStatus {
    return { ...this.status };
  }
}

// Singleton
let sidecar: StewardSidecar | null = null;
export function getStewardSidecar(): StewardSidecar {
  if (!sidecar) sidecar = new StewardSidecar();
  return sidecar;
}
```

### 2.3 Integration with AgentManager

Modify `apps/app/electrobun/src/native/agent.ts`:

```typescript
// In AgentManager.start()

async start(): Promise<AgentStatus> {
  // ... existing validation ...

  // Start Steward sidecar BEFORE agent runtime
  const steward = getStewardSidecar();
  const stewardStatus = await steward.start();
  
  if (stewardStatus.state !== "running") {
    diagnosticLog(`[Agent] Steward sidecar failed: ${stewardStatus.error}`);
    // Continue anyway — plugin will fall back to local signing
  } else {
    diagnosticLog(`[Agent] Steward sidecar ready at :${stewardStatus.port}`);
  }

  // Inject Steward env vars into agent process
  const childEnv: Record<string, string> = {
    ...(process.env as Record<string, string>),
    STEWARD_API_URL: `http://127.0.0.1:${STEWARD_PORT}`,
    STEWARD_LOCAL_MODE: "true",
    // Agent-scoped token generated by sidecar
    STEWARD_AGENT_TOKEN: await steward.getAgentToken(),
  };

  // ... spawn agent process ...
}
```

### 2.4 Bundling Steward in Desktop Build

Update build configuration to include Steward:

```typescript
// apps/app/electrobun/scripts/bundle-milady-dist.ts

async function bundleMiladyDist() {
  // ... existing agent bundling ...
  
  // Bundle Steward API
  const stewardRoot = path.resolve(__dirname, "../../../../steward-fi");
  const stewardDist = path.join(outputDir, "steward");
  
  await fs.mkdir(stewardDist, { recursive: true });
  
  // Build Steward for embedding
  await $`cd ${stewardRoot} && bun run build:embedded`;
  
  // Copy built output
  await fs.cp(
    path.join(stewardRoot, "dist/embedded"),
    stewardDist,
    { recursive: true }
  );
}
```

New build target in `steward-fi/package.json`:

```json
{
  "scripts": {
    "build:embedded": "tsup --entry packages/api/src/embedded-entry.ts --format esm --target node22 --outDir dist/embedded"
  }
}
```

---

## 3. Auto-Generate Wallets on First Launch

### 3.1 Flow: dex's First-Launch Experience

```
┌─────────────────────────────────────────────────────────────────────┐
│  App First Launch                                                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User opens Milady desktop app for first time                     │
│                                                                      │
│  2. StewardSidecar starts → creates vault DB                         │
│                                                                      │
│  3. Steward detects no local identity → auto-provisions:             │
│     ├── Generate EVM keypair (secp256k1)                             │
│     ├── Generate Solana keypair (ed25519)                            │
│     ├── Encrypt both with master password                            │
│     ├── Apply LOCAL_DEFAULT_POLICIES                                 │
│     └── Return identity to agent                                     │
│                                                                      │
│  4. Onboarding shows:                                                │
│     ┌────────────────────────────────────────┐                       │
│     │  "Your wallet is ready!"               │                       │
│     │                                        │                       │
│     │  EVM:    0x7a3b...4f2e                 │                       │
│     │  Solana: 8Kfp...9xZm                   │                       │
│     │                                        │                       │
│     │  Your wallet is secured locally.       │                       │
│     │  Use it to sign in to Eliza Cloud.     │                       │
│     │                                        │                       │
│     │  [ Back Up Wallet ] [ Continue ]       │                       │
│     └────────────────────────────────────────┘                       │
│                                                                      │
│  5. User can optionally export recovery phrase (not shown by default)│
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 New Steward API Endpoints for Local Mode

```typescript
// packages/api/src/routes/local.ts

/**
 * Local-mode only endpoints.
 * Only available when STEWARD_LOCAL_MODE=true.
 */

import { Hono } from "hono";
import { Vault } from "@stwd/vault";

const localRouter = new Hono();

/**
 * GET /local/identity
 * 
 * Returns the local user's wallet identity.
 * Auto-provisions if none exists and STEWARD_AUTO_PROVISION=true.
 */
localRouter.get("/identity", async (c) => {
  const vault = c.get("vault") as Vault;
  
  let identity = await vault.getLocalIdentity();
  
  if (!identity && process.env.STEWARD_AUTO_PROVISION === "true") {
    identity = await vault.provisionLocalIdentity({
      generateEvm: true,
      generateSolana: true,
      applyDefaultPolicies: true,
    });
  }
  
  if (!identity) {
    return c.json({ ok: false, error: "No local identity" }, 404);
  }
  
  return c.json({
    ok: true,
    data: {
      evmAddress: identity.evmAddress,
      solanaAddress: identity.solanaAddress,
      createdAt: identity.createdAt,
    },
  });
});

/**
 * POST /local/identity/provision
 * 
 * Explicitly provision a local identity (if not using auto-provision).
 */
localRouter.post("/identity/provision", async (c) => {
  const vault = c.get("vault") as Vault;
  const body = await c.req.json<{
    generateEvm?: boolean;
    generateSolana?: boolean;
  }>();
  
  const existing = await vault.getLocalIdentity();
  if (existing) {
    return c.json({ ok: false, error: "Identity already exists" }, 409);
  }
  
  const identity = await vault.provisionLocalIdentity({
    generateEvm: body.generateEvm ?? true,
    generateSolana: body.generateSolana ?? true,
    applyDefaultPolicies: true,
  });
  
  return c.json({ ok: true, data: identity });
});

/**
 * GET /local/identity/backup
 * 
 * Returns encrypted backup data (user must provide their password).
 * Never returns raw keys over HTTP.
 */
localRouter.post("/identity/backup", async (c) => {
  const vault = c.get("vault") as Vault;
  const { userPassword } = await c.req.json<{ userPassword: string }>();
  
  if (!userPassword || userPassword.length < 8) {
    return c.json({ ok: false, error: "Password must be at least 8 characters" }, 400);
  }
  
  const backup = await vault.createEncryptedBackup(userPassword);
  
  return c.json({
    ok: true,
    data: {
      encryptedBackup: backup.encrypted, // Base64 AES-256-GCM blob
      hint: "Decrypt with your backup password to restore on another device",
    },
  });
});

export { localRouter };
```

### 3.3 Vault Extensions for Local Identity

```typescript
// packages/vault/src/local-identity.ts

import { generateEvmKeypair, generateSolanaKeypair } from "./keygen";
import { KeyStore } from "./keystore";

interface LocalIdentity {
  evmAddress: string;
  solanaAddress: string;
  createdAt: string;
}

interface ProvisionOptions {
  generateEvm: boolean;
  generateSolana: boolean;
  applyDefaultPolicies: boolean;
}

const LOCAL_IDENTITY_ID = "__local_user__";

export async function provisionLocalIdentity(
  keyStore: KeyStore,
  db: Database,
  options: ProvisionOptions
): Promise<LocalIdentity> {
  let evmAddress = "";
  let solanaAddress = "";
  
  if (options.generateEvm) {
    const evmKeys = generateEvmKeypair();
    evmAddress = evmKeys.address;
    await keyStore.storeKey(db, LOCAL_IDENTITY_ID, "evm", evmKeys.privateKey);
  }
  
  if (options.generateSolana) {
    const solanaKeys = generateSolanaKeypair();
    solanaAddress = solanaKeys.publicKey;
    await keyStore.storeKey(db, LOCAL_IDENTITY_ID, "solana", solanaKeys.secretKey);
  }
  
  const createdAt = new Date().toISOString();
  
  // Store identity metadata
  await db.run(
    `INSERT INTO local_identity (id, evm_address, solana_address, created_at) VALUES (?, ?, ?, ?)`,
    [LOCAL_IDENTITY_ID, evmAddress, solanaAddress, createdAt]
  );
  
  if (options.applyDefaultPolicies) {
    await applyLocalDefaultPolicies(db, LOCAL_IDENTITY_ID);
  }
  
  return { evmAddress, solanaAddress, createdAt };
}

export async function getLocalIdentity(db: Database): Promise<LocalIdentity | null> {
  const row = await db.get(
    `SELECT evm_address, solana_address, created_at FROM local_identity WHERE id = ?`,
    [LOCAL_IDENTITY_ID]
  );
  
  if (!row) return null;
  
  return {
    evmAddress: row.evm_address,
    solanaAddress: row.solana_address,
    createdAt: row.created_at,
  };
}
```

---

## 4. Wallet-as-Identity

### 4.1 Architecture: No Separate Auth

Traditional auth flow:
```
User → Email/Password → Server validates → Session cookie → Access
```

Wallet-as-identity flow:
```
User → Wallet address → SIWE signature → Server verifies → JWT → Access
```

**Key insight:** The wallet address IS the username. No password needed — proving you control the private key (via signature) proves identity.

### 4.2 SIWE (Sign-In With Ethereum) Flow

```
┌─────────────────┐                    ┌──────────────────┐
│ Desktop App     │                    │ Eliza Cloud API   │
└────────┬────────┘                    └─────────┬─────────┘
         │                                       │
         │  1. GET /auth/siwe/nonce               │
         │ ─────────────────────────────────────► │
         │                                       │
         │  2. { nonce: "abc123", expiresAt: ... } │
         │ ◄───────────────────────────────────── │
         │                                       │
         │  3. Sign message via embedded Steward  │
         │     (SIWE message format)              │
         │                                       │
         │  4. POST /auth/siwe/verify             │
         │     { message, signature, address }    │
         │ ─────────────────────────────────────► │
         │                                       │
         │  5. Server verifies signature          │
         │     ├── Recovers signer address        │
         │     ├── Checks nonce validity          │
         │     ├── Creates/finds user record      │
         │     └── Issues JWT                     │
         │                                       │
         │  6. { token: "jwt...", user: {...} }   │
         │ ◄───────────────────────────────────── │
         │                                       │
```

### 4.3 SIWE Message Format

```
waifu.fun wants you to sign in with your Ethereum account:
0x7a3b8c...4f2e

Sign in to Eliza Cloud

URI: https://cloud.milady.ai
Version: 1
Chain ID: 1
Nonce: a1b2c3d4
Issued At: 2026-03-22T02:48:00.000Z
Expiration Time: 2026-03-22T03:48:00.000Z
```

### 4.4 Eliza Cloud Registration

When a new wallet signs in for the first time:

```typescript
// eliza-cloud-v2-milady-pack/packages/api/src/auth/siwe.ts

async function handleSiweVerify(message: string, signature: string) {
  const siwe = new SiweMessage(message);
  const { address } = await siwe.verify({ signature });
  
  // Check if user exists
  let user = await db.query.users.findFirst({
    where: eq(users.walletAddress, address),
  });
  
  if (!user) {
    // First-time sign-in: auto-register
    user = await db.insert(users).values({
      id: crypto.randomUUID(),
      walletAddress: address,
      createdAt: new Date(),
      // No email, no password — wallet IS the identity
    }).returning();
    
    // Create default org for this user
    await createPersonalOrg(user.id);
    
    console.log(`[SIWE] New user registered via wallet: ${address}`);
  }
  
  // Issue JWT
  const token = await signJwt({
    sub: user.id,
    wallet: address,
    iat: Date.now(),
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
  });
  
  return { token, user };
}
```

### 4.5 Desktop App Integration

```typescript
// packages/app-core/src/hooks/useWalletAuth.ts

export function useWalletAuth() {
  const [status, setStatus] = useState<"disconnected" | "signing" | "connected">("disconnected");
  
  async function signIn() {
    setStatus("signing");
    
    // 1. Get nonce from cloud
    const nonceRes = await fetch(`${ELIZA_CLOUD_URL}/auth/siwe/nonce`);
    const { nonce, expiresAt } = await nonceRes.json();
    
    // 2. Build SIWE message
    const message = createSiweMessage({
      address: walletAddress,
      uri: ELIZA_CLOUD_URL,
      version: "1",
      chainId: 1,
      nonce,
      issuedAt: new Date().toISOString(),
      expirationTime: expiresAt,
    });
    
    // 3. Sign via embedded Steward
    const signature = await stewardClient.signMessage(message);
    
    // 4. Verify with cloud
    const verifyRes = await fetch(`${ELIZA_CLOUD_URL}/auth/siwe/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, signature, address: walletAddress }),
    });
    
    const { token, user } = await verifyRes.json();
    
    // 5. Store token for future requests
    await storeAuthToken(token);
    setStatus("connected");
    
    return user;
  }
  
  return { status, signIn };
}
```

---

## 5. Policy Defaults for Local Agents

### 5.1 Philosophy: User Controls Their Machine

Cloud agents need conservative policies because:
- Platform is liable for misuse
- Users may not understand the risks
- Multiple tenants share infrastructure

Local agents can be more permissive because:
- User owns the machine
- User understands they're running software
- Single-tenant (their own computer)
- User can always override

### 5.2 Local Default Policies

```typescript
// packages/vault/src/local-policies.ts

import { parseEther } from "viem";
import type { PolicyRule } from "@stwd/shared";

/**
 * Default policies for local desktop agents.
 * 
 * More permissive than cloud because user controls their machine.
 * User can tighten these via Settings UI.
 */
export const LOCAL_DEFAULT_POLICIES: PolicyRule[] = [
  {
    id: "local-auto-approve",
    type: "auto-approve-threshold",
    enabled: true,
    config: {
      // Auto-approve transactions under $50 USD equivalent
      // (using ETH price at policy creation, adjustable)
      threshold: parseEther("0.02").toString(), // ~$50 at $2500/ETH
    },
  },
  {
    id: "local-spending-limit",
    type: "spending-limit",
    enabled: true,
    config: {
      // Liberal limits — user can always override
      maxPerTx:   parseEther("1.0").toString(),    // 1 ETH per transaction
      maxPerDay:  parseEther("5.0").toString(),    // 5 ETH daily
      maxPerWeek: parseEther("20.0").toString(),   // 20 ETH weekly
    },
  },
  {
    id: "local-rate-limit",
    type: "rate-limit",
    enabled: false, // DISABLED by default for local
    config: {
      maxTxPerHour: 100,
      maxTxPerDay:  500,
    },
  },
  {
    id: "local-approved-addresses",
    type: "approved-addresses",
    enabled: false, // Whitelist disabled by default
    config: {
      addresses: [],
      mode: "whitelist",
    },
  },
  {
    id: "local-time-window",
    type: "time-window",
    enabled: false, // No time restrictions
    config: {
      allowedHours: { start: 0, end: 24 },
      allowedDays: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
    },
  },
];

// Comparison with cloud defaults:
//
// | Policy            | Cloud Default  | Local Default |
// |-------------------|----------------|---------------|
// | Auto-approve      | $10            | $50           |
// | Per-tx limit      | 0.1 ETH        | 1 ETH         |
// | Daily limit       | 0.5 ETH        | 5 ETH         |
// | Weekly limit      | 2 ETH          | 20 ETH        |
// | Rate limits       | 20 tx/day      | DISABLED      |
// | Address whitelist | Optional       | DISABLED      |
// | Time windows      | N/A            | DISABLED      |
```

### 5.3 Policy Presets

Offer user-friendly presets in settings:

```typescript
export const POLICY_PRESETS = {
  permissive: {
    name: "Permissive (Default)",
    description: "Trust your agent. Auto-approve up to $50.",
    policies: LOCAL_DEFAULT_POLICIES,
  },
  
  moderate: {
    name: "Moderate",
    description: "Ask for approval over $10. Daily limits apply.",
    policies: [
      { ...LOCAL_DEFAULT_POLICIES[0], config: { threshold: parseEther("0.004").toString() } },
      { ...LOCAL_DEFAULT_POLICIES[1], config: { maxPerDay: parseEther("1.0").toString() } },
      { ...LOCAL_DEFAULT_POLICIES[2], enabled: true },
    ],
  },
  
  strict: {
    name: "Strict",
    description: "Manual approval for everything. Address whitelist only.",
    policies: [
      { ...LOCAL_DEFAULT_POLICIES[0], config: { threshold: "0" } }, // Never auto-approve
      { ...LOCAL_DEFAULT_POLICIES[3], enabled: true }, // Enable whitelist
    ],
  },
  
  custom: {
    name: "Custom",
    description: "Configure each policy individually.",
    policies: null, // Shows full policy editor
  },
};
```

---

## 6. Settings Integration

### 6.1 Settings Section Structure

The desktop app already has a settings sidebar (see `SettingsView.tsx`). Add a new "Wallet & Security" section:

```typescript
// In SETTINGS_SECTIONS array

{
  id: "wallet-security",
  label: "settings.sections.walletsecurity.label",
  icon: Shield,
  description: "settings.sections.walletsecurity.desc",
},
```

### 6.2 Wallet Section UI

```tsx
// packages/app-core/src/components/WalletSecuritySection.tsx

export function WalletSecuritySection() {
  const { walletAddress, solanaAddress } = useLocalWallet();
  const { policies, updatePolicies } = useStewardPolicies();
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      {/* Wallet Identity Card */}
      <SectionCard
        title="Your Wallet"
        description="Auto-generated on first launch. This is your identity."
      >
        <div className="space-y-4">
          {/* EVM Address */}
          <div className="flex items-center justify-between p-3 bg-bg-accent rounded-lg">
            <div className="flex items-center gap-3">
              <EthereumIcon className="w-6 h-6" />
              <div>
                <p className="text-xs text-muted">Ethereum / Base</p>
                <p className="font-mono text-sm">{truncateAddress(walletAddress)}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <CopyButton value={walletAddress} />
              <Button variant="ghost" size="sm" onClick={() => openExplorer(walletAddress)}>
                <ExternalLink className="w-4 h-4" />
              </Button>
            </div>
          </div>
          
          {/* Solana Address */}
          <div className="flex items-center justify-between p-3 bg-bg-accent rounded-lg">
            <div className="flex items-center gap-3">
              <SolanaIcon className="w-6 h-6" />
              <div>
                <p className="text-xs text-muted">Solana</p>
                <p className="font-mono text-sm">{truncateAddress(solanaAddress)}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <CopyButton value={solanaAddress} />
            </div>
          </div>
          
          {/* Balance Display */}
          <WalletBalanceDisplay />
        </div>
      </SectionCard>
      
      {/* Policy Presets */}
      <SectionCard
        title="Spending Policies"
        description="Control what your agent can do without asking permission."
      >
        <div className="space-y-4">
          {/* Preset Selector */}
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(POLICY_PRESETS).map(([key, preset]) => (
              <button
                key={key}
                onClick={() => setSelectedPreset(key)}
                className={`p-4 rounded-lg border text-left transition-all ${
                  selectedPreset === key
                    ? "border-accent bg-accent/10"
                    : "border-border hover:border-border-hover"
                }`}
              >
                <p className="font-semibold text-sm">{preset.name}</p>
                <p className="text-xs text-muted mt-1">{preset.description}</p>
              </button>
            ))}
          </div>
          
          {/* Auto-Approve Slider */}
          {selectedPreset !== "strict" && (
            <div className="space-y-2">
              <label className="text-sm font-medium">Auto-approve up to:</label>
              <div className="flex items-center gap-4">
                <Slider
                  min={0}
                  max={100}
                  step={5}
                  value={[autoApproveUsd]}
                  onValueChange={([v]) => setAutoApproveUsd(v)}
                />
                <span className="font-mono text-sm w-16">${autoApproveUsd}</span>
              </div>
            </div>
          )}
          
          {/* Advanced: Custom Policy Editor */}
          {selectedPreset === "custom" && (
            <PolicyEditor
              policies={policies}
              onChange={updatePolicies}
            />
          )}
        </div>
      </SectionCard>
      
      {/* Backup & Recovery */}
      <SectionCard
        title="Backup & Recovery"
        description="Export your wallet for recovery or migration."
      >
        <div className="space-y-4">
          <p className="text-sm text-muted">
            Your wallet keys are encrypted locally. Export a backup to recover
            on another device or if you reinstall.
          </p>
          
          <Button
            variant="outline"
            onClick={() => setShowBackupDialog(true)}
          >
            <Download className="w-4 h-4 mr-2" />
            Export Encrypted Backup
          </Button>
          
          <Button
            variant="ghost"
            onClick={() => setShowRecoveryDialog(true)}
          >
            <Upload className="w-4 h-4 mr-2" />
            Restore from Backup
          </Button>
        </div>
      </SectionCard>
      
      {/* Eliza Cloud Connection */}
      <SectionCard
        title="Eliza Cloud"
        description="Sign in to access cloud features with your wallet."
      >
        <CloudConnectionStatus />
      </SectionCard>
    </div>
  );
}
```

### 6.3 Policy Editor Component

```tsx
// packages/app-core/src/components/PolicyEditor.tsx

interface PolicyEditorProps {
  policies: PolicyRule[];
  onChange: (policies: PolicyRule[]) => void;
}

export function PolicyEditor({ policies, onChange }: PolicyEditorProps) {
  return (
    <div className="space-y-4 border-t border-border pt-4">
      <h4 className="text-sm font-semibold">Advanced Policy Settings</h4>
      
      {policies.map((policy) => (
        <PolicyRuleEditor
          key={policy.id}
          policy={policy}
          onChange={(updated) => {
            onChange(policies.map(p => p.id === policy.id ? updated : p));
          }}
        />
      ))}
      
      <Button variant="outline" size="sm" onClick={addCustomRule}>
        <Plus className="w-4 h-4 mr-2" />
        Add Custom Rule
      </Button>
    </div>
  );
}

function PolicyRuleEditor({ policy, onChange }: { policy: PolicyRule; onChange: (p: PolicyRule) => void }) {
  const { t } = useApp();
  
  return (
    <div className="p-3 border border-border rounded-lg">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Switch
            checked={policy.enabled}
            onCheckedChange={(enabled) => onChange({ ...policy, enabled })}
          />
          <span className="text-sm font-medium">
            {t(`policy.type.${policy.type}`)}
          </span>
        </div>
        <Badge variant={policy.enabled ? "default" : "secondary"}>
          {policy.enabled ? "Active" : "Disabled"}
        </Badge>
      </div>
      
      {/* Type-specific config UI */}
      {policy.type === "spending-limit" && (
        <SpendingLimitConfig
          config={policy.config}
          onChange={(config) => onChange({ ...policy, config })}
        />
      )}
      
      {policy.type === "rate-limit" && (
        <RateLimitConfig
          config={policy.config}
          onChange={(config) => onChange({ ...policy, config })}
        />
      )}
      
      {/* etc. for other policy types */}
    </div>
  );
}
```

---

## 7. Implementation Phases

### Phase 1: Embedded Steward Sidecar (1 week)

| Task | Effort | Priority |
|------|--------|----------|
| Create `steward-sidecar.ts` module | 2 days | P0 |
| Add `build:embedded` target to steward-fi | 1 day | P0 |
| Integrate sidecar launch with AgentManager | 1 day | P0 |
| Bundle Steward in desktop build scripts | 1 day | P0 |
| Test on macOS, Windows, Linux | 1 day | P0 |

**Deliverable:** Desktop app starts embedded Steward alongside agent runtime.

### Phase 2: Local Identity & Auto-Provisioning (1 week)

| Task | Effort | Priority |
|------|--------|----------|
| Add `/local/*` routes to Steward API | 1 day | P0 |
| Implement `provisionLocalIdentity()` in vault | 1 day | P0 |
| Add local identity DB schema (SQLite) | 0.5 days | P0 |
| Master password keychain integration (macOS) | 1 day | P0 |
| Master password credential manager (Windows) | 1 day | P1 |
| First-launch onboarding UI | 1 day | P0 |

**Deliverable:** First launch auto-generates EVM + Solana wallets.

### Phase 3: Wallet-as-Identity for Cloud (1 week)

| Task | Effort | Priority |
|------|--------|----------|
| Add SIWE auth endpoints to Eliza Cloud | 2 days | P0 |
| Create `useWalletAuth` hook | 1 day | P0 |
| Update CloudDashboard to support wallet auth | 1 day | P0 |
| Test SIWE flow end-to-end | 1 day | P0 |
| Handle wallet-based user creation | 0.5 days | P0 |

**Deliverable:** Users can sign into Eliza Cloud using their auto-generated wallet.

### Phase 4: Policy Defaults & Settings UI (1 week)

| Task | Effort | Priority |
|------|--------|----------|
| Define LOCAL_DEFAULT_POLICIES | 0.5 days | P0 |
| Create policy presets | 0.5 days | P0 |
| Build WalletSecuritySection component | 2 days | P0 |
| Build PolicyEditor component | 1.5 days | P1 |
| Add backup/restore UI | 1 day | P1 |
| Connect settings to Steward API | 0.5 days | P0 |

**Deliverable:** Users can view wallet, adjust policies, and export backups in Settings.

### Phase 5: Polish & Documentation (3 days)

| Task | Effort | Priority |
|------|--------|----------|
| Error handling and edge cases | 1 day | P0 |
| User-facing documentation | 0.5 days | P1 |
| Developer documentation | 0.5 days | P1 |
| E2E tests for local flow | 1 day | P1 |

**Total estimated timeline:** 4-5 weeks

---

## 8. Security Considerations

### 8.1 Master Password Protection

The master password encrypts all keys in the local vault. Security measures:

| Platform | Storage Method | Protection |
|----------|---------------|------------|
| macOS | Keychain Services | Hardware-backed, biometric unlock |
| Windows | Credential Manager | DPAPI encryption |
| Linux | libsecret / file | File permissions (fallback) |

**Never:** Store master password in plaintext, environment variables, or log files.

### 8.2 Key Export Restrictions

- Export requires explicit user action + confirmation dialog
- Exports are always encrypted with user-provided password
- Raw private keys never sent over HTTP, never logged
- Backup files warn users about security implications

### 8.3 Local Vault Isolation

- Vault DB file permissions: `0600` (owner read/write only)
- Steward process runs with minimal capabilities
- Keys decrypted only ephemerally during signing
- No key material in agent process memory

### 8.4 SIWE Security

- Nonces are single-use, server-generated
- Messages include expiration time (1 hour max)
- Chain ID prevents replay across networks
- Domain binding prevents phishing

---

## 9. Open Questions

### 9.1 Key Backup UX

**Question:** Should we show a recovery phrase by default, or only on explicit request?

**Options:**
- A) Show 12-word mnemonic on first launch (like MetaMask)
- B) Hide by default, require explicit "Back Up" action (recommended)
- C) Never show raw mnemonic, only encrypted backup files

**Recommendation:** Option B — most users won't need it, and it reduces exposure risk.

### 9.2 Multi-Device Sync

**Question:** How do users access the same wallet on multiple devices?

**Options:**
- A) Manual export/import (encrypted backup file)
- B) Cloud-synced vault (Steward service stores encrypted keys)
- C) Hardware wallet integration (user brings their own)

**Recommendation:** Start with A, add B as premium feature later.

### 9.3 Wallet Recovery Without Backup

**Question:** What if a user loses their device and has no backup?

**Answer:** Keys are gone. This is the trade-off for self-custody. We should:
- Clearly warn during onboarding
- Prompt for backup periodically
- Offer cloud backup option (Phase 2)

### 9.4 Solana Integration Priority

**Question:** Should Solana wallet be generated alongside EVM, or opt-in?

**Recommendation:** Generate both by default. Storage cost is negligible, and users increasingly expect multi-chain support.

### 9.5 Existing Wallet Import

**Question:** Can users import an existing wallet instead of auto-generating?

**Options:**
- A) No — always generate fresh (simplest)
- B) Yes — import via mnemonic or private key
- C) Yes — connect external wallet (WalletConnect)

**Recommendation:** Start with A, add B for power users who want to bring existing keys.

---

## Appendix A: File Structure

```
steward-fi/
├── packages/
│   ├── api/
│   │   └── src/
│   │       ├── routes/
│   │       │   └── local.ts           # NEW: Local-mode endpoints
│   │       └── embedded-entry.ts      # NEW: Entry point for embedded mode
│   ├── vault/
│   │   └── src/
│   │       ├── local-identity.ts      # NEW: Local identity provisioning
│   │       └── local-policies.ts      # NEW: Default policies for local
│   └── db/
│       └── src/
│           └── local-schema.ts        # NEW: SQLite schema for local mode

milaidy-dev/
├── apps/app/electrobun/
│   └── src/
│       └── native/
│           └── steward-sidecar.ts     # NEW: Sidecar lifecycle manager
├── packages/app-core/
│   └── src/
│       ├── components/
│       │   ├── WalletSecuritySection.tsx  # NEW: Settings section
│       │   └── PolicyEditor.tsx           # NEW: Policy management UI
│       └── hooks/
│           ├── useLocalWallet.ts          # NEW: Local wallet state
│           ├── useStewardPolicies.ts      # NEW: Policy management
│           └── useWalletAuth.ts           # NEW: SIWE auth flow
```

---

## Appendix B: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STEWARD_LOCAL_MODE` | `false` | Enable local-only features |
| `STEWARD_AUTO_PROVISION` | `true` | Auto-create wallet on first request |
| `STEWARD_DB_PATH` | `~/.config/Milady/steward/vault.sqlite` | Vault database location |
| `STEWARD_MASTER_PASSWORD` | (keychain) | Encryption key for vault |
| `STEWARD_PORT` | `7860` | Local API port |

---

*Last updated: 2026-03-22*
