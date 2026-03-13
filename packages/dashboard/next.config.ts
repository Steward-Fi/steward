import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@steward/sdk", "@steward/shared"],
  output: "standalone",
};

export default nextConfig;
