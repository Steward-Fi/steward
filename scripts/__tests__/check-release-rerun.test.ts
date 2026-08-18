import { describe, expect, it } from "bun:test";
import { checkReleaseRerun, classifyReleaseResponse } from "../check-release-rerun";

describe("release rerun preflight", () => {
  it("serializes release runs per tag so concurrent reruns cannot pass together", async () => {
    const workflow = await Bun.file(
      new URL("../../.github/workflows/release.yml", import.meta.url),
    ).text();
    expect(workflow).toContain("group: release-${{ github.ref }}");
    expect(workflow).toContain("cancel-in-progress: false");
  });

  it("permits a missing release and recoverable draft", () => {
    expect(classifyReleaseResponse(404, undefined, "v1.2.3")).toBe("missing");
    expect(classifyReleaseResponse(200, { draft: true, tag_name: "v1.2.3" }, "v1.2.3")).toBe(
      "draft",
    );
  });

  it("fails closed for an already-published release", () => {
    expect(classifyReleaseResponse(200, { draft: false, tag_name: "v1.2.3" }, "v1.2.3")).toBe(
      "published",
    );
  });

  it("rejects malformed, mismatched, and failed responses", () => {
    expect(() => classifyReleaseResponse(200, { draft: true }, "v1.2.3")).toThrow();
    expect(() =>
      classifyReleaseResponse(200, { draft: true, tag_name: "v9.9.9" }, "v1.2.3"),
    ).toThrow();
    expect(() => classifyReleaseResponse(403, undefined, "v1.2.3")).toThrow();
  });

  it("rejects an oversized chunked response before parsing it", async () => {
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`{"padding":"${"x".repeat(2 * 1024 * 1024)}`));
        controller.enqueue(new TextEncoder().encode('"}'));
        controller.close();
      },
    });
    await expect(
      checkReleaseRerun(
        "Steward-Fi/steward",
        "v1.2.3",
        "token",
        (async () => new Response(oversized, { status: 200 })) as typeof fetch,
      ),
    ).rejects.toThrow("exceeded 2 MiB");
  });

  it("rejects an oversized Content-Length before reading the body", async () => {
    await expect(
      checkReleaseRerun(
        "Steward-Fi/steward",
        "v1.2.3",
        "token",
        (async () =>
          new Response("{}", {
            status: 200,
            headers: { "Content-Length": String(2 * 1024 * 1024 + 1) },
          })) as typeof fetch,
      ),
    ).rejects.toThrow("exceeded 2 MiB");
  });

  it("finds a tagless draft through the bounded authenticated release list", async () => {
    const capturedUrls: string[] = [];
    let capturedAuthorization = "";
    let capturedRedirect: RequestRedirect | undefined;
    let capturedSignal: AbortSignal | null | undefined;
    const state = await checkReleaseRerun("Steward-Fi/steward", "v1.2.3", "test-secret", (async (
      input,
      init,
    ) => {
      capturedUrls.push(String(input));
      capturedAuthorization = new Headers(init?.headers).get("authorization") ?? "";
      capturedRedirect = init?.redirect;
      capturedSignal = init?.signal;
      if (capturedUrls.length === 1) return new Response("not found", { status: 404 });
      return Response.json([{ tag_name: "v1.2.3", draft: true }]);
    }) as typeof fetch);
    expect(state).toBe("draft");
    expect(capturedUrls).toEqual([
      "https://api.github.com/repos/Steward-Fi/steward/releases/tags/v1.2.3",
      "https://api.github.com/repos/Steward-Fi/steward/releases?per_page=100&page=1",
    ]);
    expect(capturedAuthorization).toBe("Bearer test-secret");
    expect(capturedRedirect).toBe("error");
    expect(capturedSignal).toBeInstanceOf(AbortSignal);
  });

  it("permits a truly missing release only after scanning drafts", async () => {
    let calls = 0;
    const state = await checkReleaseRerun(
      "Steward-Fi/steward",
      "v1.2.3",
      "test-secret",
      (async () => {
        calls += 1;
        return calls === 1 ? new Response("not found", { status: 404 }) : Response.json([]);
      }) as typeof fetch,
    );
    expect(state).toBe("missing");
    expect(calls).toBe(2);
  });

  it("continues through full release-list pages and finds a later draft", async () => {
    const firstPage = Array.from({ length: 100 }, (_, index) => ({
      tag_name: `v1.0.${index}`,
      draft: false,
    }));
    const requestedUrls: string[] = [];
    const state = await checkReleaseRerun("Steward-Fi/steward", "v2.0.0", "token", (async (
      input,
    ) => {
      const url = String(input);
      requestedUrls.push(url);
      if (requestedUrls.length === 1) return new Response("not found", { status: 404 });
      if (url.endsWith("page=1")) return Response.json(firstPage);
      return Response.json([{ tag_name: "v2.0.0", draft: true }]);
    }) as typeof fetch);
    expect(state).toBe("draft");
    expect(requestedUrls.at(-1)).toEndWith("page=2");
  });

  it("fails closed when authenticated draft listing is unauthorized or malformed", async () => {
    for (const listResponse of [
      new Response("forbidden", { status: 403 }),
      Response.json({ tag_name: "v1.2.3", draft: true }),
      Response.json([{ tag_name: "v1.2.3" }]),
      Response.json([{ draft: true }]),
    ]) {
      let calls = 0;
      await expect(
        checkReleaseRerun("Steward-Fi/steward", "v1.2.3", "token", (async () => {
          calls += 1;
          return calls === 1 ? new Response("not found", { status: 404 }) : listResponse;
        }) as typeof fetch),
      ).rejects.toThrow();
    }
  });

  it("runs the preflight before dependency installation and publication writes", async () => {
    const workflow = await Bun.file(
      new URL("../../.github/workflows/release.yml", import.meta.url),
    ).text();
    const preflight = workflow.indexOf("Verify release tag is unpublished");
    expect(preflight).toBeGreaterThan(0);
    for (const laterStep of [
      "Install dependencies",
      "Publish @stwd/sdk",
      "Publish @stwd/react",
      "Publish @stwd/eliza-plugin",
      "Create GitHub Release",
    ]) {
      expect(workflow.indexOf(laterStep)).toBeGreaterThan(preflight);
    }
    expect(workflow).toContain("permissions:\n      contents: write");
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

  it("refuses the repository's tombstoned legacy draft before fetch", async () => {
    const neverFetch = (async () => {
      throw new Error("fetch should not run");
    }) as typeof fetch;
    await expect(
      checkReleaseRerun("Steward-Fi/steward", "v0.3.16", "token", neverFetch),
    ).rejects.toThrow("tombstoned legacy draft");
  });
});
