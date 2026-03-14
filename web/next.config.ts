import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const config: NextConfig = {
  outputFileTracingRoot: path.join(__dirname, ".."),
  reactStrictMode: true,
  transpilePackages: ["@steward/sdk", "@steward/shared"],
};

export default config;
