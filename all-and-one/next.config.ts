import path from "path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  transpilePackages: ["three"],
  webpack: (config) => {
    config.resolve.alias["@locale"] = path.join(__dirname, "../antbb/locale");
    return config;
  },
};

export default nextConfig;
