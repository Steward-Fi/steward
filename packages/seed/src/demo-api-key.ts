import { generateApiKey } from "../../auth/src/api-keys";
import type { ApiKeyPair } from "../../auth/src/types";

/**
 * Mint a fresh credential for each demo seed run.
 *
 * Demo data may be loaded into an internet-reachable environment, so a
 * repository-known key is unsafe even when the package is primarily intended
 * for local development.
 */
export function generateDemoApiKey(): ApiKeyPair {
  return generateApiKey();
}
