import { describe, expect, test } from "bun:test";
import {
  hostPatternsOverlap,
  methodPatternsOverlap,
  pathPatternsOverlap,
} from "../services/governed-route-inventory";

describe("governed route overlap semantics", () => {
  test("detects broad and narrow host overlap without matching sibling domains", () => {
    expect(hostPatternsOverlap("*.example.com", "api.example.com")).toBe(true);
    expect(hostPatternsOverlap("*.example.com", "*.sub.example.com")).toBe(true);
    expect(hostPatternsOverlap("*.example.com", "example.com")).toBe(false);
    expect(hostPatternsOverlap("*.example.com", "api.example.net")).toBe(false);
  });

  test("detects wildcard path and method intersections", () => {
    expect(pathPatternsOverlap("/v1/*", "/v1/secrets")).toBe(true);
    expect(pathPatternsOverlap("/v1/*", "/v2/*")).toBe(false);
    expect(pathPatternsOverlap("/*", "/anything")).toBe(true);
    expect(methodPatternsOverlap("*", "POST")).toBe(true);
    expect(methodPatternsOverlap("GET", "post")).toBe(false);
  });
});
