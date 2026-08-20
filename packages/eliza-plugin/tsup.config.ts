import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  external: ["@elizaos/core", "@stwd/sdk"],
  // Keep Steward's shared runtime helpers inside the published artifact. A
  // workspace protocol dependency cannot be installed from an npm tarball,
  // and both the root and sensitive-keys subpath are used at runtime.
  noExternal: ["@stwd/shared", "@stwd/shared/sensitive-keys"],
  target: "node22",
});
