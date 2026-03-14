import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@stwd/sdk", "@stwd/shared"],
  webpack: (config) => {
    config.resolve.fallback = {
      ...config.resolve.fallback,
      "pino-pretty": false,
    };
    // Fix for @metamask/sdk react-native import
    config.externals = config.externals || [];
    return config;
  },
};

export default config;
