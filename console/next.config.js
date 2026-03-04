// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Proxy API calls to the FastAPI backend during development
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
