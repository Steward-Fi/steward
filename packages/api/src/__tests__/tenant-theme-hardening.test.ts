import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("tenant theme hardening", () => {
  it("normalizes tenant appearance tokens before persistence", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");

    expect(source).toContain("function normalizeTenantTheme");
    expect(source).toContain("must be a 6-digit hex color");
    expect(source).toContain("theme.borderRadius must be a number between 0 and 32");
    expect(source).toContain("theme.fontFamily contains unsupported characters");
    expect(source).toContain("theme.colorScheme must be light, dark, or system");
    expect(source).toContain("const theme = normalizeTenantTheme(body.theme)");
  });

  it("documents and exposes appearance controls through dashboard settings", () => {
    const settings = read("web/src/app/dashboard/settings/page.tsx");
    const docs = read("docs/api-reference/tenant-config.mdx");

    expect(settings).toContain("Save Appearance");
    expect(settings).toContain('data-testid="appearance-preview"');
    expect(settings).toContain("themePayloadFromForm");
    expect(settings).toContain("themeFormFromConfig(data.data.theme)");
    expect(docs).toContain("## Theme Config");
  });
});
