import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("passkey login options privacy", () => {
  it("does not expose stored credential ids before authentication", () => {
    const routeStart = authSource.indexOf('auth.post("/passkey/login/options"');
    const routeEnd = authSource.indexOf('auth.post("/passkey/login/verify"', routeStart);
    const routeBody = authSource.slice(routeStart, routeEnd);

    expect(routeBody).not.toContain("authenticators.credentialId");
    expect(routeBody).not.toContain("authenticators.userId");
    expect(routeBody).toContain("allowCredentials: []");
  });
});
