import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  external: ["@elizaos/core", "@stwd/sdk"],
  noExternal: ["@stwd/shared/sensitive-keys"],
  target: "node22",
});
