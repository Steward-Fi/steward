/**
 * Tests for the PROVIDER-MODES registry + manifest-identifier grammar (A1).
 */

import { describe, expect, test } from "bun:test";
import {
  formatManifestIdentifier,
  PROVIDER_MODES,
  parseManifestIdentifier,
  providerModeEntry,
  resolveProviderMode,
} from "../provider-modes";

describe("provider modes", () => {
  test("discord is broker (cannot down-scope a bot token)", () => {
    expect(resolveProviderMode("discord")).toBe("broker");
  });

  test("github is broker until Steward mints a real installation token", () => {
    expect(resolveProviderMode("github")).toBe("broker");
  });

  test("llm and wallet are broker", () => {
    expect(resolveProviderMode("llm")).toBe("broker");
    expect(resolveProviderMode("wallet")).toBe("broker");
  });

  test("unknown provider defaults to broker (fail-safe)", () => {
    expect(resolveProviderMode("totally-unknown")).toBe("broker");
    expect(providerModeEntry("totally-unknown").mode).toBe("broker");
  });

  test("resolution is case-insensitive", () => {
    expect(resolveProviderMode("DisCord")).toBe("broker");
    expect(resolveProviderMode("GITHUB")).toBe("broker");
  });

  test("registry entries all carry a rationale", () => {
    for (const e of PROVIDER_MODES) {
      expect(e.rationale.length).toBeGreaterThan(20);
      expect(["token", "broker"]).toContain(e.mode);
    }
  });
});

describe("manifest identifier grammar", () => {
  test("parses provider:kind", () => {
    const id = parseManifestIdentifier("llm:pool-seat");
    expect(id).not.toBeNull();
    expect(id?.provider).toBe("llm");
    expect(id?.kind).toBe("pool-seat");
    expect(id?.agent).toBeUndefined();
    expect(id?.raw).toBe("llm:pool-seat");
  });

  test("parses provider:kind:agent", () => {
    const id = parseManifestIdentifier("discord:bot-token:soliza");
    expect(id?.provider).toBe("discord");
    expect(id?.kind).toBe("bot-token");
    expect(id?.agent).toBe("soliza");
    expect(id?.raw).toBe("discord:bot-token:soliza");
  });

  test("normalizes case", () => {
    expect(parseManifestIdentifier("Discord:Bot-Token")?.raw).toBe("discord:bot-token");
  });

  test("rejects malformed identifiers (fail closed)", () => {
    expect(parseManifestIdentifier("")).toBeNull();
    expect(parseManifestIdentifier("onlyprovider")).toBeNull();
    expect(parseManifestIdentifier("a:b:c:d")).toBeNull();
    expect(parseManifestIdentifier("bad char:kind")).toBeNull();
    expect(parseManifestIdentifier(":kind")).toBeNull();
    expect(parseManifestIdentifier(null as unknown as string)).toBeNull();
  });

  test("round-trips through format", () => {
    expect(formatManifestIdentifier({ provider: "github", kind: "app", agent: "org" })).toBe(
      "github:app:org",
    );
    expect(formatManifestIdentifier({ provider: "wallet", kind: "sign" })).toBe("wallet:sign");
  });
});
