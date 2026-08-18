import { describe, expect, it } from "bun:test";
import { checkReleaseRerun, classifyReleaseResponse } from "../check-release-rerun";

describe("release rerun preflight", () => {
  it("permits a missing release and recoverable draft", () => {
    expect(classifyReleaseResponse(404, undefined, "v1.2.3")).toBe("missing");
    expect(
      classifyReleaseResponse(200, { draft: true, tag_name: "v1.2.3" }, "v1.2.3"),
    ).toBe("draft");
  });

  it("fails closed for an already-published release", () => {
    expect(
      classifyReleaseResponse(200, { draft: false, tag_name: "v1.2.3" }, "v1.2.3"),
    ).toBe("published");
  });

  it("rejects malformed, mismatched, and failed responses", () => {
    expect(() => classifyReleaseResponse(200, { draft: true }, "v1.2.3")).toThrow();
    expect(() =>
      classifyReleaseResponse(200, { draft: true, tag_name: "v9.9.9" }, "v1.2.3"),
    ).toThrow();
    expect(() => classifyReleaseResponse(403, undefined, "v1.2.3")).toThrow();
  });

  it("finds a tagless draft through the bounded authenticated release list", async () => {
    const capturedUrls: string[] = [];
    let capturedAuthorization = "";
    const state = await checkReleaseRerun(
      "Steward-Fi/steward",
      "v1.2.3",
      "test-secret",
      (async (input, init) => {
        capturedUrls.push(String(input));
        capturedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
        if (capturedUrls.length === 1) return new Response("not found", { status: 404 });
        return Response.json([{ tag_name: "v1.2.3", draft: true }]);
      }) as typeof fetch,
    );
    expect(state).toBe("draft");
    expect(capturedUrls).toEqual([
      "https://api.github.com/repos/Steward-Fi/steward/releases/tags/v1.2.3",
      "https://api.github.com/repos/Steward-Fi/steward/releases?per_page=100&page=1",
    ]);
    expect(capturedAuthorization).toBe("Bearer test-secret");
  });

  it("permits a truly missing release only after scanning drafts", async () => {
    let calls = 0;
    const state = await checkReleaseRerun(
      "Steward-Fi/steward",
      "v1.2.3",
      "test-secret",
      (async () => {
        calls += 1;
        return calls === 1
          ? new Response("not found", { status: 404 })
          : Response.json([]);
      }) as typeof fetch,
    );
    expect(state).toBe("missing");
    expect(calls).toBe(2);
  });

  it("rejects attacker-controlled repository and tag inputs before fetch", async () => {
    const neverFetch = (async () => {
      throw new Error("fetch should not run");
    }) as typeof fetch;
    await expect(
      checkReleaseRerun("example/repo/extra", "v1.2.3", "token", neverFetch),
    ).rejects.toThrow("Invalid GITHUB_REPOSITORY");
    await expect(
      checkReleaseRerun("example/repo", "not-a-release", "token", neverFetch),
    ).rejects.toThrow("bounded v* tag");
  });
});
