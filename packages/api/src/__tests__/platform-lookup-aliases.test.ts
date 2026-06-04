import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const platformSource = readFileSync(join(import.meta.dir, "..", "routes", "platform.ts"), "utf8");

describe("platform user lookup aliases", () => {
  it("exposes Privy-style lookup aliases through the shared lookup path", () => {
    for (const route of [
      'platform.post("/users/email/address"',
      'platform.post("/users/phone/number"',
      'platform.post("/users/wallet/address"',
      'platform.post("/users/smart-wallet/address"',
      'platform.post("/users/custom-auth/id"',
      'platform.post("/users/discord/username"',
      'platform.post("/users/github/username"',
      'platform.post("/users/farcaster/id"',
      'platform.post("/users/instagram/username"',
      'platform.post("/users/spotify/subject"',
      'platform.post("/users/telegram/user-id"',
      'platform.post("/users/telegram/username"',
      'platform.post("/users/twitch/username"',
      'platform.post("/users/twitter/subject"',
      'platform.post("/users/twitter/username"',
    ]) {
      expect(platformSource).toContain(route);
    }

    expect(platformSource).toContain("lookupPlatformUserIdentity(");
    expect(platformSource).toContain("PLATFORM_READ_ONLY_POST_PATHS");
    expect(platformSource).toContain("isPlatformReadLikeRequest(c)");
    expect(platformSource).toContain('requirePlatformRouteScope(c, "platform:user:read")');
    expect(platformSource).toContain("providerLookupAlias(");
  });
});
