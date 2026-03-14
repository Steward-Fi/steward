import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@stwd/sdk", "@stwd/shared"],
};

export default config;
