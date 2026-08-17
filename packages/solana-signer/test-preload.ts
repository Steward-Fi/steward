// Runs once per `bun test` process, before any test file's module graph
// loads (bunfig.toml [test].preload).
//
// Every fixture this suite needs is created in-process by the tests
// themselves: the stub Steward API in __tests__/harness.ts binds an ephemeral
// loopback port per file. One dependency cannot be, and gets created here
// instead: steward-signer.ts imports @stwd/sdk, whose package entry is
// dist/index.js, a tsc build output absent from a clean checkout. The preload
// runs the sdk's own `bun run build` when that entry is missing or older than
// any sdk source file. typescript arrives with the root `bun install`, so a
// clean checkout needs nothing beyond install + `bun test`.
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const sdkDir = join(import.meta.dir, "..", "sdk");
const distEntry = join(sdkDir, "dist", "index.js");

function newestMtimeMs(dir: string): number {
  let newest = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    newest = Math.max(newest, entry.isDirectory() ? newestMtimeMs(path) : statSync(path).mtimeMs);
  }
  return newest;
}

const stale =
  !existsSync(distEntry) || statSync(distEntry).mtimeMs < newestMtimeMs(join(sdkDir, "src"));

if (stale) {
  const build = Bun.spawnSync(["bun", "run", "build"], {
    cwd: sdkDir,
    stdout: "inherit",
    stderr: "inherit",
  });
  if (build.exitCode !== 0) {
    throw new Error(
      `@stwd/sdk build failed (exit ${build.exitCode}); the signer tests import its dist entry`,
    );
  }
}
