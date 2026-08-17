/**
 * SEC-192: describeContributions() builds its result with a null-prototype
 * object so a plugin literally named "__proto__" cannot vanish — assigning
 * `out["__proto__"]` on a plain {} sets the prototype instead of an own
 * property, silently dropping the plugin from JSON diagnostics.
 */
import { describe, expect, it } from "bun:test";
import { WebhookEventRegistry } from "../webhook-event-registry";

describe("WebhookEventRegistry.describeContributions (SEC-192)", () => {
  it('a plugin named "__proto__" survives as an own property', () => {
    const registry = new WebhookEventRegistry(["core.event"]);
    registry.registerPluginEvents("__proto__", ["odd.event"]);
    registry.registerPluginEvents("normal-plugin", ["normal.event"]);

    const contributions = registry.describeContributions();

    expect(Object.hasOwn(contributions, "__proto__")).toBe(true);
    expect(contributions["__proto__" as keyof typeof contributions]).toEqual(["odd.event"]);
    expect(contributions["normal-plugin"]).toEqual(["normal.event"]);
    // And the result survives the JSON diagnostics round-trip intact.
    expect(JSON.parse(JSON.stringify(contributions))).toEqual({
      __proto__: ["odd.event"],
      "normal-plugin": ["normal.event"],
    });
  });

  it("registry lookups are unaffected by the __proto__ plugin name", () => {
    const registry = new WebhookEventRegistry(["core.event"]);
    registry.registerPluginEvents("__proto__", ["odd.event"]);

    expect(registry.has("core.event")).toBe(true);
    expect(registry.has("odd.event")).toBe(true);
    expect(registry.has("missing.event")).toBe(false);
  });
});
