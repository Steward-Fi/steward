/**
 * plugin-config.test.ts — unit tests for the deploy-time plugin enablement
 * resolver (`resolveEnabledPlugins`).
 *
 * Covers:
 *   - LEAN: unset / empty / whitespace-only STEWARD_PLUGINS → empty set.
 *   - FULL: "trading" → { trading }; case + whitespace normalization.
 *   - legacy boolean: STEWARD_ENABLE_TRADING=true → { trading }.
 *   - combined: STEWARD_PLUGINS + legacy boolean union (no duplicate).
 *   - fail-closed: an unknown plugin name throws UnknownPluginError.
 *
 * The resolver is env-injectable, so these tests pass a plain object and never
 * touch process.env — pure + hermetic.
 */

import { describe, expect, it } from "bun:test";
import { KNOWN_PLUGIN_NAMES, resolveEnabledPlugins, UnknownPluginError } from "../plugin-config";

describe("resolveEnabledPlugins — LEAN (no plugins)", () => {
  it("returns an empty set when STEWARD_PLUGINS is unset", () => {
    expect([...resolveEnabledPlugins({})]).toEqual([]);
  });

  it("returns an empty set when STEWARD_PLUGINS is an empty string", () => {
    expect([...resolveEnabledPlugins({ STEWARD_PLUGINS: "" })]).toEqual([]);
  });

  it("returns an empty set when STEWARD_PLUGINS is whitespace only", () => {
    expect([...resolveEnabledPlugins({ STEWARD_PLUGINS: "   " })]).toEqual([]);
  });

  it("drops empty entries between commas without enabling anything", () => {
    expect([...resolveEnabledPlugins({ STEWARD_PLUGINS: ",, ," })]).toEqual([]);
  });
});

describe("resolveEnabledPlugins — FULL (trading)", () => {
  it("enables trading for STEWARD_PLUGINS=trading", () => {
    const enabled = resolveEnabledPlugins({ STEWARD_PLUGINS: "trading" });
    expect(enabled.has("trading")).toBe(true);
    expect(enabled.size).toBe(1);
  });

  it("trims surrounding whitespace", () => {
    expect(resolveEnabledPlugins({ STEWARD_PLUGINS: "  trading  " }).has("trading")).toBe(true);
  });

  it("lowercases the name (case-insensitive)", () => {
    expect(resolveEnabledPlugins({ STEWARD_PLUGINS: "TRADING" }).has("trading")).toBe(true);
    expect(resolveEnabledPlugins({ STEWARD_PLUGINS: "TrAdInG" }).has("trading")).toBe(true);
  });

  it("dedupes a repeated name", () => {
    const enabled = resolveEnabledPlugins({ STEWARD_PLUGINS: "trading, trading ,TRADING" });
    expect([...enabled]).toEqual(["trading"]);
  });
});

describe("resolveEnabledPlugins — legacy STEWARD_ENABLE_TRADING", () => {
  it("enables trading for STEWARD_ENABLE_TRADING=true", () => {
    expect(resolveEnabledPlugins({ STEWARD_ENABLE_TRADING: "true" }).has("trading")).toBe(true);
  });

  it("is case-insensitive + trims for the legacy boolean", () => {
    expect(resolveEnabledPlugins({ STEWARD_ENABLE_TRADING: "  TRUE " }).has("trading")).toBe(true);
  });

  it("does NOT enable trading for non-true values", () => {
    for (const v of ["false", "1", "yes", "", "  "]) {
      expect([...resolveEnabledPlugins({ STEWARD_ENABLE_TRADING: v })]).toEqual([]);
    }
  });

  it("unions with STEWARD_PLUGINS without duplicating", () => {
    const enabled = resolveEnabledPlugins({
      STEWARD_PLUGINS: "trading",
      STEWARD_ENABLE_TRADING: "true",
    });
    expect([...enabled]).toEqual(["trading"]);
  });

  it("adds trading via legacy bool even when STEWARD_PLUGINS is empty", () => {
    const enabled = resolveEnabledPlugins({
      STEWARD_PLUGINS: "",
      STEWARD_ENABLE_TRADING: "true",
    });
    expect([...enabled]).toEqual(["trading"]);
  });
});

describe("resolveEnabledPlugins — fail-closed on unknown plugin", () => {
  it("throws UnknownPluginError for an unknown name", () => {
    expect(() => resolveEnabledPlugins({ STEWARD_PLUGINS: "bogus" })).toThrow(UnknownPluginError);
  });

  it("throws if any name in a list is unknown (even alongside a known one)", () => {
    expect(() => resolveEnabledPlugins({ STEWARD_PLUGINS: "trading,bogus" })).toThrow(
      UnknownPluginError,
    );
  });

  it("error message names the offending plugin + the known set", () => {
    try {
      resolveEnabledPlugins({ STEWARD_PLUGINS: "nope" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(UnknownPluginError);
      expect((err as Error).message).toContain("nope");
      expect((err as Error).message).toContain("trading");
    }
  });

  it("the legacy boolean only ever adds a KNOWN name (cannot trip the guard)", () => {
    // STEWARD_ENABLE_TRADING can only add "trading", which is known — so it never
    // throws regardless of value.
    expect(() => resolveEnabledPlugins({ STEWARD_ENABLE_TRADING: "true" })).not.toThrow();
  });
});

describe("KNOWN_PLUGIN_NAMES", () => {
  it("contains trading and nothing unexpected", () => {
    expect(KNOWN_PLUGIN_NAMES.has("trading")).toBe(true);
    expect([...KNOWN_PLUGIN_NAMES]).toEqual(["trading"]);
  });
});
