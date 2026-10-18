import { afterEach, describe, expect, test } from "bun:test";
import { decideApproval, getCase, ProviderActionError } from "./provider-actions";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function respond(body: string, status: number, contentType = "text/plain"): void {
  const mockedFetch = async () =>
    new Response(body, { status, headers: { "Content-Type": contentType } });
  globalThis.fetch = Object.assign(mockedFetch, { preconnect: originalFetch.preconnect });
}

describe("provider action response normalization", () => {
  for (const status of [403, 404]) {
    test(`collapses non-JSON ${status} without exposing parser diagnostics`, async () => {
      respond("<html>private upstream response</html>", status, "text/html");

      await expect(getCase("action", "token", "tenant")).rejects.toEqual(
        expect.objectContaining({
          name: "ProviderActionError",
          code: "not found / not authorized",
          httpStatus: status,
        }),
      );
    });
  }

  test("preserves HTTP status when a server error body is HTML", async () => {
    respond("<html>gateway failure</html>", 502, "text/html");

    await expect(getCase("action", "token", "tenant")).rejects.toEqual(
      expect.objectContaining({ code: "HTTP 502", httpStatus: 502 }),
    );
  });

  test("preserves a structured API error code", async () => {
    respond(JSON.stringify({ ok: false, error: { code: "APPROVAL_FIELD_INVALID" } }), 400);

    await expect(
      decideApproval(
        "action",
        {
          decision: "approve",
          reason: "reviewed",
          expectedVersion: 1,
          expectedRequestHash: "sha256:request",
          expectedActionDigest: "sha256:action",
        },
        "token",
        "tenant",
      ),
    ).rejects.toEqual(expect.objectContaining({ code: "APPROVAL_FIELD_INVALID", httpStatus: 400 }));
  });

  test("normalizes malformed successful responses", async () => {
    respond("not-json", 200);

    await expect(getCase("action", "token", "tenant")).rejects.toEqual(
      new ProviderActionError("invalid JSON response", 200),
    );
  });
});
