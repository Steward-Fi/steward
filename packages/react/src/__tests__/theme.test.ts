import { describe, expect, test } from "bun:test";
import { DEFAULT_THEME, mergeTheme } from "../utils/theme.js";

describe("theme utilities", () => {
  test("mergeTheme preserves tenant appearance asset URLs", () => {
    const theme = mergeTheme(DEFAULT_THEME, {
      logoUrl: "https://assets.example.test/logo.png",
      faviconUrl: "https://assets.example.test/favicon.ico",
    });

    expect(theme.logoUrl).toBe("https://assets.example.test/logo.png");
    expect(theme.faviconUrl).toBe("https://assets.example.test/favicon.ico");
  });
});
