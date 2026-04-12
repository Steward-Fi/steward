#!/usr/bin/env bun

import { spawnSync } from "node:child_process";

const stewardUrl = process.env.STEWARD_URL?.trim();

if (!stewardUrl) {
  console.log(
    "[steward-fi] Skipping e2e smoke because STEWARD_URL is not configured.",
  );
  process.exit(0);
}

const result = spawnSync("bun", ["run", "scripts/e2e-auth-test.ts"], {
  cwd: process.cwd(),
  stdio: "inherit",
  env: process.env,
});

process.exit(result.status ?? 1);
