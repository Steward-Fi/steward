import { describe, expect, test } from "bun:test";
import {
  matchSecretRouteHost,
  matchSecretRoutePath,
  secretRouteHostPatternsOverlap,
  secretRoutePathPatternsOverlap,
} from "../secret-route-matching";

describe("shared secret-route matching", () => {
  test("host intersection agrees with runtime matching over exact and nested wildcard witnesses", () => {
    const patterns = [
      "api.example.com",
      "other.example.com",
      "*.example.com",
      "*.sub.example.com",
      "example.com",
      "api.example.net",
    ];
    const hosts = [
      "api.example.com",
      "other.example.com",
      "x.sub.example.com",
      "deep.sub.example.com",
      "example.com",
      "api.example.net",
    ];
    for (const left of patterns) {
      for (const right of patterns) {
        const hasWitness = hosts.some(
          (host) => matchSecretRouteHost(left, host) && matchSecretRouteHost(right, host),
        );
        expect(secretRouteHostPatternsOverlap(left, right)).toBe(hasWitness);
      }
    }
  });

  test("path intersection agrees with runtime matching over broad/narrow witnesses", () => {
    const patterns = ["/*", "*", "/v1/*", "/v1/read/*", "/v1/read", "/v2/*", "/v2/x"];
    const paths = ["/", "/x", "/v1/x", "/v1/read", "/v1/read/x", "/v2/x", "/v2/y"];
    for (const left of patterns) {
      for (const right of patterns) {
        const hasWitness = paths.some(
          (path) => matchSecretRoutePath(left, path) && matchSecretRoutePath(right, path),
        );
        expect(secretRoutePathPatternsOverlap(left, right)).toBe(hasWitness);
      }
    }
  });
});
