// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * SEC-154: the dashboard auth guard is client-only, so unauthenticated users
 * receive the full dashboard HTML/JS. That is acceptable ONLY while no page
 * under /dashboard renders data server-side. This test guards the invariant:
 * every page/layout/route file in the dashboard tree must stay client-rendered
 * ("use client") so nothing sensitive can be embedded in the streamed HTML.
 */

const DASHBOARD_DIR = join(import.meta.dir);

function collectFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFiles(path));
    } else if (/^(page|layout)\.(tsx|ts|jsx|js)$/.test(entry.name)) {
      out.push(path);
    }
  }
  return out;
}

describe("dashboard pages stay client-rendered (SEC-154)", () => {
  const files = collectFiles(DASHBOARD_DIR);

  test("the dashboard tree is non-empty", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  test("every dashboard page/layout starts with a 'use client' directive", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      // The directive must be the first statement of the module.
      if (!/^\s*"use client"/.test(source)) {
        offenders.push(file.slice(DASHBOARD_DIR.length + 1));
      }
    }
    expect(offenders).toEqual([]);
  });
});
