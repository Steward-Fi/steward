/**
 * smoke.test.ts - the facade can't silently lose an export.
 *
 * the sdk is a curated re-export surface; a refactor in @stwd/shared or @stwd/api
 * could drop a symbol the sdk promises. this asserts every RUNTIME symbol the sdk
 * re-exports is defined, and (at compile time) that every TYPE the sdk promises is
 * importable + usable. if either regresses, this file fails to typecheck/run.
 */

import { describe, expect, it } from "bun:test";
// types the sdk re-exports. imported type-only; the `_typeProbe` below references
// each so an accidental removal is a compile error, not a silent drop.
import type {
  AdapterContribution,
  ContributedPolicyResult,
  ContributedPolicyRule,
  LoadedPluginInfo,
  PluginHostDiagnostics,
  PluginMigrationSource,
  PolicyRuleContribution,
  StewardApiPlugin,
  StewardApp,
  StewardAppContext,
  StewardPlugin,
} from "../index";
// runtime values the sdk re-exports (the host runtime).
import { buildPluginContext, PluginHost, PluginHostError, registerPlugin } from "../index";

describe("@stwd/plugin-sdk facade", () => {
  it("re-exports every runtime symbol (defined, correct kind)", () => {
    expect(typeof buildPluginContext).toBe("function");
    expect(typeof registerPlugin).toBe("function");
    expect(typeof PluginHost).toBe("function"); // class constructor
    expect(typeof PluginHostError).toBe("function"); // class constructor
  });

  it("PluginHostError is a real Error subclass", () => {
    const err = new PluginHostError("boom");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("PluginHostError");
    expect(err.message).toBe("boom");
  });

  it("a fresh PluginHost describes an empty load", () => {
    const host = new PluginHost<Record<string, never>>();
    const d = host.describe();
    expect(d.plugins).toEqual([]);
    expect(Array.isArray(d.webhookEvents)).toBe(true);
    expect(d.policyRuleContributions).toEqual({});
    expect(d.adapterContributions).toEqual({});
  });
});

// ── compile-time probe: every promised TYPE is importable + usable ────────────
//
// this never runs; it exists so `tsc --noEmit` fails if the sdk drops a type
// re-export. each type is referenced once.
type _TypeProbe = {
  plugin: StewardPlugin;
  apiPlugin: StewardApiPlugin;
  app: StewardApp;
  ctx: StewardAppContext;
  policyContribution: PolicyRuleContribution;
  contributedRule: ContributedPolicyRule;
  contributedResult: ContributedPolicyResult;
  migration: PluginMigrationSource;
  adapter: AdapterContribution;
  diagnostics: PluginHostDiagnostics;
  loaded: LoadedPluginInfo;
};
// reference the probe so it isn't an "unused type" lint hit.
export type __SdkTypeProbe = _TypeProbe;
