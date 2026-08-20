// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const pageSource = readFileSync(join(import.meta.dir, "page.tsx"), "utf8");

/**
 * SEC-075: merely opening /accept-invitation?tenantId=X&token=Y while signed
 * in must NOT join the tenant. The POST fires only from an explicit "Accept
 * invitation" click; the page renders a confirmation step first.
 */
describe("accept-invitation requires explicit confirmation (SEC-075)", () => {
  test("the accept POST is never fired from an effect on page load", () => {
    // No useEffect in the component at all — acceptance is click-driven only.
    expect(pageSource).not.toContain("useEffect");
    // The POST helper is invoked exclusively inside the click handler.
    const calls = pageSource.split("acceptInvitation(tenantId, token, sessionToken)");
    expect(calls).toHaveLength(2); // one call site only
    expect(pageSource).toContain("function handleAccept()");
    expect(pageSource).toContain("onClick={handleAccept}");
  });

  test("an explicit Accept + Decline confirmation step is rendered", () => {
    expect(pageSource).toMatch(/>\s*Accept invitation\s*<\/button>/);
    expect(pageSource).toMatch(/>\s*Decline\s*<\/Link>/);
    expect(pageSource).toContain("showConfirm");
  });
});
