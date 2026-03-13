import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@steward/sdk", "@steward/shared"],
};

export default config;
