// OpenNext Cloudflare adapter config.
// Defaults are correct for a Next 15 App Router app deployed to Workers:
// the nonce-based CSP middleware in src/middleware.ts runs on the Workers
// runtime (Web Crypto getRandomValues is supported), and the single dynamic
// route is server-rendered on demand by the Worker.
import { defineCloudflareConfig } from "@opennextjs/cloudflare";

const config = defineCloudflareConfig();

// Pin the inner Next build to bun (the repo's package manager). Without this
// OpenNext can shell out to `npm run build`, which may resolve a different Node
// runtime than the one driving the adapter.
config.buildCommand = "bun run build";

export default config;
