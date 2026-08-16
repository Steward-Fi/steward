import { describe, expect, test } from "bun:test";
import {
  secretRouteHostPatternsOverlap,
  secretRouteMethodPatternsOverlap,
  secretRoutePathPatternsOverlap,
} from "@stwd/shared";

describe("governed route overlap semantics", () => {
  test("detects broad and narrow host overlap without matching sibling domains", () => {
    expect(secretRouteHostPatternsOverlap("*.example.com", "api.example.com")).toBe(true);
    expect(secretRouteHostPatternsOverlap("*.example.com", "*.sub.example.com")).toBe(true);
    expect(secretRouteHostPatternsOverlap("*.example.com", "example.com")).toBe(false);
    expect(secretRouteHostPatternsOverlap("*.example.com", "api.example.net")).toBe(false);
  });

  test("detects wildcard path and method intersections", () => {
    expect(secretRoutePathPatternsOverlap("/v1/*", "/v1/secrets")).toBe(true);
    expect(secretRoutePathPatternsOverlap("/v1/*", "/v2/*")).toBe(false);
    expect(secretRoutePathPatternsOverlap("/*", "/anything")).toBe(true);
    expect(secretRouteMethodPatternsOverlap("*", "POST")).toBe(true);
    expect(secretRouteMethodPatternsOverlap("GET", "post")).toBe(false);
  });
});
