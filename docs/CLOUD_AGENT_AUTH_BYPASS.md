# Cloud Agent Auth Bypass — Root Cause Analysis & Fixes

**Date:** 2026-03-20
**Branch:** `fix/cloud-agent-auth-flow` (milaidy-dev, not pushed)
**Status:** Fixes identified and implemented

---

## Problem Statement

When a user creates an agent through Eliza Cloud and clicks "Open Web UI", they get a pairing/login screen even though they're already authenticated. The platform already knows who they are — zero-friction auth handoff should happen automatically.

## Architecture Overview

```
User clicks "Open Web UI" on Dashboard
        │
        ▼
  open-web-ui.ts (homepage app)
        │
        ├── POST /api/v1/milady/agents/{uuid}/pairing-token  (cloud backend @ port 3000)
        │   Returns: { token: <one-time-token>, redirectUrl: "https://<uuid>.waifu.fun/pair?token=<token>" }
        │
        ▼
  Browser popup opens redirectUrl
        │
        ├── OPTION A: /?token=<jwt>  →  nginx Lua intercept
        │   Lua fetches MILADY_API_TOKEN from agent-lookup (port 3456)
        │   Returns inline JS: sessionStorage.setItem("milady_api_token", "<real-key>")
        │
        └── OPTION B: /pair?token=<one-time-token>  →  pair.html (static)
            pair.html POSTs to /api/auth/pair  →  cloud backend (port 3000)
            Backend validates token, looks up sandbox, returns MILADY_API_TOKEN
            pair.html stores in sessionStorage, redirects to /
                │
                ▼
          Container UI loads (app-core MiladyClient)
          Reads sessionStorage("milady_api_token")
          Sends as Authorization: Bearer <token> on every request
          If token valid → auth passes → GET /api/onboarding/status → {complete: true} → chat
          If token missing → GET /api/auth/status → {required: true} → pairing screen
```

## Root Causes (3 independent failures)

### RC-1: Agent Discovery Service Missing Endpoints (CRITICAL)

**File:** `/home/shad0w/projects/milady-hosted-image/milady-discovery.cjs`
**Port:** 3456

The nginx Lua router (`/etc/nginx/lua/agent-router.lua`) intercepts `GET /?token=...` and makes an internal subrequest to:
- `/agent-lookup/agents/<uuid>/headscale-ip` — for routing
- `/agent-apikey/agents/<uuid>/api-key` — for token injection

Both map to port 3456. **But the discovery service only had `/agents` (list all)**. It was missing:
- `/agents/:uuid/headscale-ip` — individual agent routing lookup
- `/agents/:uuid/api-key` — API token lookup

**Result:** Every Lua token injection attempt returned 404 → fell through to normal proxy → user sees pairing screen.

**Fix:** Added both endpoints to `milady-discovery.cjs`:
- `GET /agents/:uuid/headscale-ip` → returns `{ target: "ip:port" }` using headscale_ip or node_id→tailscale mapping
- `GET /agents/:uuid/api-key` → returns `{ apiKey: "milady_..." }` from environment_vars

Also added `NODE_TAILSCALE_IPS` mapping since `headscale_ip` is NULL for most running agents (they use node_id + tailscale routing).

**Status:** ✅ Fixed and deployed (service restarted)

### RC-2: Origin Mismatch in Pairing Token Validation (CRITICAL)

**Files:**
- `apps/homepage/src/lib/open-web-ui.ts` (milaidy-dev)
- `packages/lib/services/pairing-token.ts` (eliza-cloud-v2)

**Flow:**
1. Dashboard calls `POST /api/v1/milady/agents/<uuid>/pairing-token`
2. Backend creates token with `expected_origin = "https://<uuid>.waifu.fun"` (from `getMiladyAgentPublicWebUiUrl`)
3. Backend returns `redirectUrl = "https://<uuid>.waifu.fun/pair?token=<token>"`
4. `open-web-ui.ts` calls `rewriteAgentUiUrl(redirectUrl)` which changes `.waifu.fun` → `.milady.ai`
5. Browser opens `https://<uuid>.milady.ai/pair?token=<token>`
6. `pair.html` sends POST to `/api/auth/pair` with `Origin: https://<uuid>.milady.ai`
7. Token validation checks `expected_origin = "https://<uuid>.waifu.fun"` vs `Origin: "https://<uuid>.milady.ai"`
8. **MISMATCH → validation fails → pairing fails**

**Fix (two-pronged):**

1. **open-web-ui.ts** (committed to `fix/cloud-agent-auth-flow`): Stop calling `rewriteAgentUiUrl()` on the pairing redirect URL. The pairing flow should use the original domain. URL rewriting only matters for user-facing URLs after auth completes.

2. **pairing-token.ts** (eliza-cloud-v2, defense-in-depth): Added alternate domain matching — if exact origin fails, try the aliased domain (waifu.fun ↔ milady.ai). This makes the system resilient even if URLs get rewritten by CDNs, proxies, or future code changes.

**Status:** ✅ Fixed in both repos

### RC-3: Headscale IP NULL for All Running Agents (MODERATE)

**Table:** `milady_sandboxes`

All running agents have `headscale_ip = NULL`. They use `node_id` (e.g., "milady-core-1") which maps to a tailscale IP (`100.64.0.4`) for routing. The original discovery service didn't handle this case.

**Current mapping:**
```
milady-core-1 → 100.64.0.4
milady-core-2 → 100.64.0.5
shad0wbot     → 100.64.0.3
agent-node-1  → 100.64.0.1
nyx-node      → 100.64.0.2
```

**Fix:** Added `NODE_TAILSCALE_IPS` fallback mapping in the discovery service. When `headscale_ip` is NULL, resolves via `node_id`.

**Status:** ✅ Fixed

## Onboarding Flow (RC-4, potential issue)

Even with perfect auth, the container may show onboarding if the agent hasn't been through the onboarding flow. The app-core startup checks:

1. `GET /api/auth/status` → `{ required: true/false, pairingEnabled: true/false }`
2. If auth passes: `GET /api/onboarding/status` → `{ complete: true/false }`
3. If `complete: false` → shows onboarding wizard (provider selection, etc.)

**For cloud-provisioned agents:**
- The `cloudOnly` branding flag is set in `apps/app/src/main.tsx` → skips "wakeUp" step, defaults to cloud mode
- The cloud backend sets `ELIZAOS_CLOUD_API_KEY` and `ELIZAOS_CLOUD_ENABLED=true` → onboarding detects cloud connection
- When the container receives the onboarding POST, `extractAndPersistOnboardingApiKey()` saves the API key

**Risk:** If a cloud-provisioned container has never been accessed, the first visitor sees the onboarding flow even after auth succeeds. This is **by design** for the Milady desktop app (where users set up their own agent), but for cloud agents created via the dashboard, onboarding should be pre-completed.

**Recommendation:** Cloud provisioning should POST to `/api/onboarding` with the cloud configuration as part of container setup, so the container starts with `complete: true`.

## What Changed (Files Modified)

### Applied fixes:

| File | Repo | Change |
|------|------|--------|
| `apps/homepage/src/lib/open-web-ui.ts` | milaidy-dev | Don't rewrite pairing redirect URL |
| `milady-discovery.cjs` | milady-hosted-image | Add `/agents/:uuid/headscale-ip` and `/agents/:uuid/api-key` endpoints + tailscale IP mapping |
| `packages/lib/services/pairing-token.ts` | eliza-cloud-v2 | Add alternate domain matching (waifu.fun ↔ milady.ai) |

### Not modified (already correct):

| File | Status |
|------|--------|
| `agent-router.lua` (nginx Lua) | Already handles `/?token=` intercept correctly; was blocked by missing discovery endpoints |
| `pair.html` | Already correctly exchanges pairing token → API key → sessionStorage |
| `server.ts` (container auth) | Already reads `milady_api_token` from sessionStorage correctly |
| `cloud-connection.ts` | Cloud detection logic is correct |
| `cloud-routes.ts` | Route handling is correct |
| `DesktopOnboardingRuntime.tsx` | Desktop-only, not relevant to cloud flow |

## The Ideal Flow (After Fixes)

```
1. User clicks "Open Web UI" on dashboard
2. open-web-ui.ts fetches pairing token from cloud backend
3. Cloud backend creates one-time token + redirect URL (waifu.fun domain)
4. Popup opens redirect URL (NOT rewritten to milady.ai)
5. pair.html exchanges token → gets MILADY_API_TOKEN
6. Stores in sessionStorage, redirects to /
7. Container loads, reads token from sessionStorage
8. Auth passes, onboarding already complete (cloud-provisioned)
9. User lands in chat — zero friction ✨
```

**Alternative (faster) path via Lua:**
```
1. Dashboard opens /?token=<any-value> on agent subdomain
2. Nginx Lua intercepts, fetches MILADY_API_TOKEN from discovery service
3. Returns inline JS that stores token + redirects to /
4. No round-trip to cloud backend needed
```

## Steward Integration Impact

When Steward manages agent provisioning:

1. **Token injection:** Steward creates the container with `MILADY_API_TOKEN` in env vars. No change needed — the discovery service reads from `environment_vars` regardless of who provisioned the container.

2. **Auth flow:** Same pairing token flow works. The cloud backend looks up the sandbox by UUID and returns `environment_vars.MILADY_API_TOKEN`.

3. **Steward-specific improvement:** Steward could inject tokens via its own API instead of relying on `environment_vars` column. This would require:
   - A Steward endpoint: `POST /api/steward/agents/:uuid/session-token`
   - The endpoint would generate a short-lived JWT signed with Steward's key
   - The Lua router would call Steward instead of the discovery service
   - Benefit: tokens rotate, no long-lived MILADY_API_TOKEN in DB

4. **Onboarding bypass:** Steward should POST to the container's `/api/onboarding` endpoint during provisioning with the cloud config, so the container starts with onboarding already complete.

## Testing

```bash
# Verify discovery endpoints work
curl -s http://127.0.0.1:3456/agents/<uuid>/headscale-ip
# → {"target":"100.64.0.4:23644"}

curl -s http://127.0.0.1:3456/agents/<uuid>/api-key
# → {"apiKey":"milady_ceb692..."}

# Verify Lua intercept works (from browser or curl with Host header)
curl -s -H "Host: <uuid>.waifu.fun" "http://127.0.0.1:8080/?token=anything"
# → HTML with inline JS that sets sessionStorage

# Verify pairing flow works
# 1. Get pairing token from cloud backend
# 2. Open /pair?token=<token> in browser
# 3. Should redirect to / with auth cookie
```
