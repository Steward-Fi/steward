/**
 * Unit tests for the governed query-forwarding chokepoint.
 *
 * These exercise `extractRawQuery` and `applyGovernedQuery` directly, covering
 * the encoding/duplicate-key preservation contract and the fail-closed security
 * rejections (base query on the target, userinfo, fragment, altered authority)
 * that are awkward to reach through the full proxy integration path.
 */

import { describe, expect, test } from "bun:test";
import { applyGovernedQuery, extractRawQuery } from "../handlers/query-forwarding";

describe("extractRawQuery", () => {
  test("returns empty string when there is no query", () => {
    expect(extractRawQuery("http://localhost/github/x")).toBe("");
  });

  test("normalizes a bare '?' to empty", () => {
    expect(extractRawQuery("http://localhost/github/x?")).toBe("");
  });

  test("preserves ordered duplicate keys and strips the fragment", () => {
    expect(extractRawQuery("http://localhost/github/x?a=1&a=2&b=3#frag")).toBe("?a=1&a=2&b=3");
  });

  test("preserves percent-encoding verbatim", () => {
    expect(extractRawQuery("http://localhost/github/x?q=a%2Fb%20c&sig=%2B%3D")).toBe(
      "?q=a%2Fb%20c&sig=%2B%3D",
    );
  });

  test("fails closed to empty on an unparseable url", () => {
    expect(extractRawQuery("::::not a url::::")).toBe("");
  });
});

describe("applyGovernedQuery", () => {
  const target = () => new URL("https://api.github.com/repos/acme/widgets/issues");

  test("applies a simple query and pins the authority/path", () => {
    const result = applyGovernedQuery(target(), "?state=open");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.protocol).toBe("https:");
    expect(result.url.host).toBe("api.github.com");
    expect(result.url.pathname).toBe("/repos/acme/widgets/issues");
    expect(result.url.search).toBe("?state=open");
  });

  test("does not mutate the input target", () => {
    const t = target();
    applyGovernedQuery(t, "?state=open");
    expect(t.search).toBe("");
  });

  test("preserves ordered duplicate keys without collapsing", () => {
    const result = applyGovernedQuery(target(), "?label=bug&label=urgent&label=p0");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.search).toBe("?label=bug&label=urgent&label=p0");
    expect(result.url.searchParams.getAll("label")).toEqual(["bug", "urgent", "p0"]);
  });

  test("preserves a blank value", () => {
    const result = applyGovernedQuery(target(), "?q=&page=2");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.search).toBe("?q=&page=2");
  });

  test("does not decode/re-encode percent-encoded values", () => {
    const result = applyGovernedQuery(target(), "?q=a%2Fb%20c&sig=%2B%3D");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.search).toBe("?q=a%2Fb%20c&sig=%2B%3D");
    expect(result.url.pathname).toBe("/repos/acme/widgets/issues");
  });

  test("accepts a raw query string without a leading '?'", () => {
    const result = applyGovernedQuery(target(), "a=1&a=2");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.search).toBe("?a=1&a=2");
  });

  test("empty query yields no search", () => {
    const result = applyGovernedQuery(target(), "");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.search).toBe("");
  });

  test("a URL-looking query value stays inert data", () => {
    const result = applyGovernedQuery(
      target(),
      `?next=${encodeURIComponent("https://evil.example.com/steal")}`,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.host).toBe("api.github.com");
    expect(result.url.pathname).toBe("/repos/acme/widgets/issues");
    expect(result.url.searchParams.get("next")).toBe("https://evil.example.com/steal");
  });

  test("rejects fail-closed when the target already carries a base query", () => {
    const withQuery = new URL("https://api.github.com/repos/acme/widgets/issues?base=1");
    const result = applyGovernedQuery(withQuery, "?state=open");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("target-carries-base-query");
  });

  test("rejects fail-closed when the target carries userinfo", () => {
    const withUser = new URL("https://user:pass@api.github.com/repos/acme/widgets/issues");
    const result = applyGovernedQuery(withUser, "?state=open");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("target-carries-userinfo");
  });

  test("rejects fail-closed when the target carries a fragment", () => {
    const withHash = new URL("https://api.github.com/repos/acme/widgets/issues#frag");
    const result = applyGovernedQuery(withHash, "?state=open");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("target-carries-fragment");
  });

  test("does not fold a fragment in the query onto the outbound url", () => {
    // `.search` treats "#" as literal query data, never a real fragment.
    const result = applyGovernedQuery(target(), "?a=1%23notfrag");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.url.hash).toBe("");
    expect(result.url.search).toBe("?a=1%23notfrag");
  });
});
